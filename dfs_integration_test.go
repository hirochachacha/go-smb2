package smb2_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/stretchr/testify/require"
)

type integrationTransport struct {
	smb2.Transport
}

// TestDFSIntegration requires a DFS root whose link refers to a writable SMB
// share. NewClient creates the referral target connection so the test covers
// credential selection, referral resolution, and reconnection.
func TestDFSIntegration(t *testing.T) {
	addr := os.Getenv("SMB2_DFS_ADDR")
	if addr == "" {
		t.Skip("SMB2_DFS_ADDR is not configured")
	}
	targetAddr := os.Getenv("SMB2_DFS_TARGET_ADDR")
	if targetAddr == "" {
		targetAddr = addr
	}
	targetServer := os.Getenv("SMB2_DFS_TARGET_SERVER")
	user := os.Getenv("SMB2_DFS_USER")
	password := os.Getenv("SMB2_DFS_PASSWORD")
	domain := os.Getenv("SMB2_DFS_DOMAIN")
	shareName := os.Getenv("SMB2_DFS_SHARE")
	linkName := os.Getenv("SMB2_DFS_LINK")
	require.NotEmpty(t, user)
	require.NotEmpty(t, password)
	require.NotEmpty(t, shareName)
	require.NotEmpty(t, linkName)
	require.NotEmpty(t, targetServer)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverName := os.Getenv("SMB2_DFS_SERVER")
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		require.NoError(t, err)
		serverName = host
	}

	var transportServersMu sync.Mutex
	var transportServers []string

	client, err := smb2.NewClient(smb2.ClientConfig{
		Credentials: smb2.NTLMCredential{User: user, Password: password, Domain: domain},
		Transport: func(ctx context.Context, requestedServer string) (smb2.Transport, error) {
			transportServersMu.Lock()
			transportServers = append(transportServers, requestedServer)
			transportServersMu.Unlock()
			var address string
			switch requestedServer {
			case serverName:
				address = addr
			case targetServer:
				address = targetAddr
			default:
				return nil, fmt.Errorf("unexpected SMB server %q", requestedServer)
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
			if err != nil {
				return nil, err
			}
			return &integrationTransport{Transport: smb2.NewDirectTCPTransport(conn)}, nil
		},
		Negotiator: smb2.Negotiator{RequireMessageSigning: true},
	})
	require.NoError(t, err)
	defer client.Close()
	shareNames, err := client.ListShareNames(ctx, serverName)
	require.NoError(t, err)
	require.Contains(t, shareNames, shareName)

	share, err := client.Mount(ctx, fmt.Sprintf(`\\%s\%s`, serverName, shareName))
	require.NoError(t, err)
	defer share.Umount()

	name := fmt.Sprintf(`%s\go-smb2-dfs-%d.txt`, linkName, time.Now().UnixNano())
	payload := []byte("DFS referral integration test\n")
	require.NoError(t, share.WriteFile(name, payload, 0o600))
	defer share.Remove(name)

	got, err := share.ReadFile(name)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	transportServersMu.Lock()
	gotServers := append([]string(nil), transportServers...)
	transportServersMu.Unlock()
	require.Equal(t, []string{serverName, serverName, targetServer}, gotServers, "cached target should reuse its transport")
}
