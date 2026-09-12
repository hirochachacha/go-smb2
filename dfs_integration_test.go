package smb2_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/stretchr/testify/require"
)

// TestDFSIntegration requires a DFS root whose link refers to a writable SMB
// share. The referral target connection is deliberately created through
// DFSConnector so the test covers both referral resolution and reconnection.
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	newDialer := func() *smb2.Dialer {
		return &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				User:     user,
				Password: password,
				Domain:   domain,
			},
			Negotiator: smb2.Negotiator{RequireMessageSigning: true},
		}
	}

	var connectorCalls atomic.Int32
	dialer := newDialer()
	dialer.DFSConnector = func(ctx context.Context, serverName string) (*smb2.Session, error) {
		if serverName == "" {
			return nil, fmt.Errorf("DFS referral returned an empty server name")
		}
		if targetServer != "" && serverName != targetServer {
			return nil, fmt.Errorf("DFS referral server %q, want %q", serverName, targetServer)
		}
		connectorCalls.Add(1)
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			return nil, err
		}
		session, err := newDialer().DialContext(ctx, conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return session, nil
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	require.NoError(t, err)
	defer conn.Close()
	session, err := dialer.DialContext(ctx, conn)
	require.NoError(t, err)
	defer session.Logoff()

	share, err := session.WithContext(ctx).Mount(shareName)
	require.NoError(t, err)
	defer share.Umount()

	name := fmt.Sprintf(`%s\go-smb2-dfs-%d.txt`, linkName, time.Now().UnixNano())
	payload := []byte("DFS referral integration test\n")
	require.NoError(t, share.WriteFile(name, payload, 0o600))
	defer share.Remove(name)
	require.Equal(t, int32(1), connectorCalls.Load())

	got, err := share.ReadFile(name)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.Equal(t, int32(1), connectorCalls.Load(), "cached target should reuse its session")
}
