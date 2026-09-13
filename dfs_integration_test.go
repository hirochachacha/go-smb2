package smb2_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/stretchr/testify/require"
)

type dfsIntegrationConfig struct {
	server, target, secondTarget string
	share, link                  string
	addresses                    map[string]string
	credentials                  smb2.NTLMCredential
}

func loadDFSIntegrationConfig(t *testing.T) dfsIntegrationConfig {
	t.Helper()
	addr := os.Getenv("SMB2_DFS_ADDR")
	if addr == "" {
		t.Skip("SMB2_DFS_ADDR is not configured")
	}
	server := os.Getenv("SMB2_DFS_SERVER")
	if server == "" {
		var err error
		server, _, err = net.SplitHostPort(addr)
		require.NoError(t, err)
	}
	target := os.Getenv("SMB2_DFS_TARGET_SERVER")
	secondTarget := os.Getenv("SMB2_DFS_SECOND_TARGET_SERVER")
	require.NotEmpty(t, target, "SMB2_DFS_TARGET_SERVER")
	require.NotEmpty(t, secondTarget, "SMB2_DFS_SECOND_TARGET_SERVER")
	require.NotEqual(t, server, target)
	require.NotEqual(t, server, secondTarget)
	require.NotEqual(t, target, secondTarget)
	targetAddr := os.Getenv("SMB2_DFS_TARGET_ADDR")
	if targetAddr == "" {
		targetAddr = addr
	}
	secondAddr := os.Getenv("SMB2_DFS_SECOND_TARGET_ADDR")
	if secondAddr == "" {
		secondAddr = addr
	}
	cfg := dfsIntegrationConfig{
		server: server, target: target, secondTarget: secondTarget,
		share: os.Getenv("SMB2_DFS_SHARE"), link: os.Getenv("SMB2_DFS_LINK"),
		addresses: map[string]string{server: addr, target: targetAddr, secondTarget: secondAddr},
		credentials: smb2.NTLMCredential{
			User: os.Getenv("SMB2_DFS_USER"), Password: os.Getenv("SMB2_DFS_PASSWORD"),
			Domain: os.Getenv("SMB2_DFS_DOMAIN"),
		},
	}
	require.NotEmpty(t, cfg.share, "SMB2_DFS_SHARE")
	require.NotEmpty(t, cfg.link, "SMB2_DFS_LINK")
	require.NotEmpty(t, cfg.credentials.User, "SMB2_DFS_USER")
	require.NotEmpty(t, cfg.credentials.Password, "SMB2_DFS_PASSWORD")
	return cfg
}

type dfsIntegrationClient struct {
	*smb2.Client
	ctx         context.Context
	mu          sync.Mutex
	connections map[string]int
}

func newDFSIntegrationClient(t *testing.T, cfg dfsIntegrationConfig) *dfsIntegrationClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	c := &dfsIntegrationClient{ctx: ctx, connections: make(map[string]int)}
	client, err := smb2.NewClient(smb2.ClientConfig{
		Credentials: cfg.credentials,
		Transport: func(ctx context.Context, server string) (smb2.Transport, error) {
			address, ok := cfg.addresses[server]
			if !ok {
				return nil, fmt.Errorf("unexpected DFS server %q", server)
			}
			c.mu.Lock()
			c.connections[server]++
			c.mu.Unlock()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
			if err != nil {
				return nil, err
			}
			return smb2.NewDirectTCPTransport(conn), nil
		},
		RequireMessageSigning: true,
	})
	require.NoError(t, err)
	c.Client = client
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	return c
}

func (c *dfsIntegrationClient) mount(t *testing.T, server, share string) *smb2.Share {
	t.Helper()
	fs, err := c.Mount(c.ctx, fmt.Sprintf(`\\%s\%s`, server, share))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, fs.Unmount(context.Background())) })
	return fs
}

func (c *dfsIntegrationClient) connectionCounts() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	counts := make(map[string]int, len(c.connections))
	for server, count := range c.connections {
		counts[server] = count
	}
	return counts
}

// The fixture has link and link-alias pointing at target/dfs-target, and
// link-extra pointing at secondTarget/dfs-encrypted/nested. The latter share
// requires SMB encryption. All three logical servers may use one Samba daemon.
func TestDFSIntegration(t *testing.T) {
	cfg := loadDFSIntegrationConfig(t)

	t.Run("referral_and_cache", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		shares, err := c.ListShareNames(c.ctx, cfg.server)
		require.NoError(t, err)
		require.Contains(t, shares, cfg.share)
		fs := c.mount(t, cfg.server, cfg.share)
		name := join(cfg.link, fmt.Sprintf("go-smb2-dfs-%d.txt", time.Now().UnixNano()))
		t.Cleanup(func() { require.NoError(t, fs.Remove(context.Background(), name)) })
		payload := []byte("DFS referral integration test\n")
		require.NoError(t, fs.WriteFile(c.ctx, name, payload, 0o600))
		before := c.connectionCounts()
		got, err := fs.ReadFile(c.ctx, name)
		require.NoError(t, err)
		require.Equal(t, payload, got)
		require.Equal(t, 1, before[cfg.target])
		require.Equal(t, before, c.connectionCounts(), "cached target should reuse its transport")
	})

	t.Run("prefixes_aliases_and_rename", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		fs := c.mount(t, cfg.server, cfg.share)
		directory := fmt.Sprintf("go-smb2-dfs-%d-日本語", time.Now().UnixNano())
		plainPath := join(cfg.link, directory, "同名.txt")
		encryptedPath := join(cfg.link+"-extra", directory, "同名.txt")
		plain := bytes.Repeat([]byte("plain"), 300000)
		encrypted := bytes.Repeat([]byte("encrypted"), 200000)
		for _, link := range []string{cfg.link, cfg.link + "-extra"} {
			path := join(link, directory)
			require.NoError(t, fs.Mkdir(c.ctx, path, 0o700))
			t.Cleanup(func() { require.NoError(t, fs.RemoveAll(context.Background(), path)) })
		}
		require.NoError(t, fs.WriteFile(c.ctx, plainPath, plain, 0o600))
		require.NoError(t, fs.WriteFile(c.ctx, encryptedPath, encrypted, 0o600))

		// Verify storage independently of namespace routing. This catches a
		// prefix collision routing link-extra into link, and a lost target base.
		plainTarget := c.mount(t, cfg.target, "dfs-target")
		encryptedTarget := c.mount(t, cfg.secondTarget, "dfs-encrypted")
		got, err := plainTarget.ReadFile(c.ctx, join(directory, "同名.txt"))
		require.NoError(t, err)
		require.Equal(t, plain, got)
		got, err = encryptedTarget.ReadFile(c.ctx, join("nested", directory, "同名.txt"))
		require.NoError(t, err)
		require.Equal(t, encrypted, got)

		aliasPath := join(cfg.link+"-alias", directory, "変更.txt")
		require.NoError(t, fs.Rename(c.ctx, plainPath, aliasPath))
		got, err = fs.ReadFile(c.ctx, join(cfg.link, directory, "変更.txt"))
		require.NoError(t, err)
		require.Equal(t, plain, got)
		_, err = fs.Stat(c.ctx, plainPath)
		require.ErrorIs(t, err, os.ErrNotExist)

		crossTarget := join(cfg.link+"-extra", directory, "移動.txt")
		require.ErrorContains(t, fs.Rename(c.ctx, aliasPath, crossTarget), "cross-device DFS rename")
		got, err = fs.ReadFile(c.ctx, aliasPath)
		require.NoError(t, err)
		require.Equal(t, plain, got, "rejected cross-target rename must preserve the source")
		_, err = fs.Stat(c.ctx, crossTarget)
		require.ErrorIs(t, err, os.ErrNotExist)
		got, err = fs.ReadFile(c.ctx, encryptedPath)
		require.NoError(t, err)
		require.Equal(t, encrypted, got)
		require.Equal(t, map[string]int{cfg.server: 1, cfg.target: 1, cfg.secondTarget: 1}, c.connectionCounts())
	})

	t.Run("concurrent_cold_referrals", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		fs := c.mount(t, cfg.server, cfg.share)
		const workers = 8
		start := make(chan struct{})
		results := make(chan error, workers)
		prefix := fmt.Sprintf("go-smb2-dfs-%d", time.Now().UnixNano())
		for i := range workers {
			link := cfg.link
			if i%2 != 0 {
				link += "-extra"
			}
			path := join(link, fmt.Sprintf("%s-%d-並行.txt", prefix, i))
			t.Cleanup(func() { require.NoError(t, fs.RemoveAll(context.Background(), path)) })
			go func() {
				<-start
				payload := bytes.Repeat([]byte(fmt.Sprintf("worker-%d", i)), 16000)
				if err := fs.WriteFile(c.ctx, path, payload, 0o600); err != nil {
					results <- fmt.Errorf("write %s: %w", path, err)
					return
				}
				got, err := fs.ReadFile(c.ctx, path)
				if err == nil && !bytes.Equal(got, payload) {
					err = fmt.Errorf("content mismatch for %s", path)
				}
				results <- err
			}()
		}
		close(start)
		// Drain all workers before cleanup, even if one worker fails.
		for range workers {
			if err := <-results; err != nil {
				t.Error(err)
			}
		}
		require.Equal(t, map[string]int{cfg.server: 1, cfg.target: 1, cfg.secondTarget: 1}, c.connectionCounts(), "concurrent misses should share target connections")
	})

	t.Run("multi_hop", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		fs := c.mount(t, cfg.server, cfg.share)
		directory := fmt.Sprintf("go-smb2-dfs-%d-多段", time.Now().UnixNano())
		chain := join(cfg.link+"-chain", directory)
		require.NoError(t, fs.Mkdir(c.ctx, chain, 0o700))
		// Cleanup uses the one-hop alias so a broken chain cannot leak files.
		t.Cleanup(func() { require.NoError(t, fs.RemoveAll(context.Background(), join(cfg.link+"-extra", directory))) })
		path := join(chain, "内容.txt")
		payload := bytes.Repeat([]byte("multiple DFS namespaces\n"), 65536)
		require.NoError(t, fs.WriteFile(c.ctx, path, payload, 0o600))
		before := c.connectionCounts()
		for range 2 {
			got, err := fs.ReadFile(c.ctx, path)
			require.NoError(t, err)
			require.Equal(t, payload, got)
		}
		require.Equal(t, before, c.connectionCounts(), "cached chain must reuse every target connection")
		require.Equal(t, map[string]int{cfg.server: 1, cfg.target: 1, cfg.secondTarget: 1}, before)

		// A fresh client must resolve the full chain for an existing file too.
		cold := newDFSIntegrationClient(t, cfg)
		coldFS := cold.mount(t, cfg.server, cfg.share)
		got, err := coldFS.ReadFile(cold.ctx, path)
		require.NoError(t, err)
		require.Equal(t, payload, got)
		final := c.mount(t, cfg.secondTarget, "dfs-encrypted")
		got, err = final.ReadFile(c.ctx, join("nested", directory, "内容.txt"))
		require.NoError(t, err)
		require.Equal(t, payload, got)

		// Both names reach the same final tree through different DFS chains.
		renamed := join(cfg.link+"-extra", directory, "変更.txt")
		require.NoError(t, fs.Rename(c.ctx, path, renamed))
		got, err = fs.ReadFile(c.ctx, join(chain, "変更.txt"))
		require.NoError(t, err)
		require.Equal(t, payload, got)
		_, err = fs.Stat(c.ctx, path)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("referral_cycle", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		fs := c.mount(t, cfg.server, cfg.share)
		ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
		defer cancel()
		_, err := fs.Stat(ctx, join(cfg.link+"-cycle", "file.txt"))
		require.ErrorContains(t, err, "DFS referral cycle")
		require.NotErrorIs(t, err, context.DeadlineExceeded)
		name := join(cfg.link, fmt.Sprintf("go-smb2-dfs-%d.txt", time.Now().UnixNano()))
		t.Cleanup(func() { require.NoError(t, fs.RemoveAll(context.Background(), name)) })
		payload := []byte("connection survives a DFS cycle")
		require.NoError(t, fs.WriteFile(c.ctx, name, payload, 0o600))
		got, err := fs.ReadFile(c.ctx, name)
		require.NoError(t, err)
		require.Equal(t, payload, got)
	})

	t.Run("unmount_preserves_other_mount", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		first := c.mount(t, cfg.server, cfg.share)
		second := c.mount(t, cfg.server, cfg.share)
		name := fmt.Sprintf("go-smb2-dfs-%d.txt", time.Now().UnixNano())
		path := join(cfg.link, name)
		t.Cleanup(func() { require.NoError(t, second.RemoveAll(context.Background(), path)) })
		payload := []byte("file bound to a shared DFS target session")
		require.NoError(t, first.WriteFile(c.ctx, path, payload, 0o600))
		file, err := second.Open(c.ctx, join(cfg.link+"-alias", name))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, file.Close(context.Background())) })
		before := c.connectionCounts()
		require.NoError(t, first.Unmount(c.ctx))
		got := make([]byte, len(payload))
		n, err := file.ReadAt(c.ctx, got, 0)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
		require.Equal(t, payload, got)
		got, err = second.ReadFile(c.ctx, path)
		require.NoError(t, err)
		require.Equal(t, payload, got)
		require.Equal(t, before, c.connectionCounts(), "unmount must not force the other mount to reconnect")

		remounted := c.mount(t, cfg.server, cfg.share)
		got, err = remounted.ReadFile(c.ctx, path)
		require.NoError(t, err)
		require.Equal(t, payload, got)
		require.Equal(t, before, c.connectionCounts())
	})
}
