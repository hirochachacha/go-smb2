package smb2

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// These variables describe a disposable AD account and writable SMB shares.
// The encrypted share must require SMB encryption on the server.
func TestKerberosIntegration(t *testing.T) {
	confPath := os.Getenv("SMB2_KRB5_CONFIG")
	if confPath == "" {
		t.Skip("SMB2_KRB5_CONFIG is not configured")
	}
	cfg, err := config.Load(confPath)
	require.NoError(t, err)
	cl := client.NewWithPassword(os.Getenv("SMB2_KRB5_USER"), os.Getenv("SMB2_KRB5_REALM"), os.Getenv("SMB2_KRB5_PASSWORD"), cfg)
	defer cl.Destroy()
	require.NoError(t, cl.Login())
	for _, dialect := range []uint16{smb2.SMB210, smb2.SMB302, smb2.SMB311} {
		t.Run(fmt.Sprintf("%04x", dialect), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			tcp, err := (&net.Dialer{}).DialContext(ctx, "tcp", os.Getenv("SMB2_KRB5_ADDR"))
			require.NoError(t, err)
			defer tcp.Close()
			d := dialer{Initiator: &KerberosInitiator{Client: cl, TargetSPN: os.Getenv("SMB2_KRB5_SPN")}, Negotiator: negotiator{RequireMessageSigning: true, SpecifiedDialect: dialect}}
			session, err := d.DialContext(ctx, tcp)
			require.NoError(t, err)
			defer session.Logoff(context.Background())
			shares := []string{os.Getenv("SMB2_KRB5_SHARE")}
			if dialect >= smb2.SMB300 {
				shares = append(shares, os.Getenv("SMB2_KRB5_ENCRYPTED_SHARE"))
			}
			for _, name := range shares {
				require.NotEmpty(t, name)
				share, err := session.Mount(ctx, name)
				require.NoError(t, err)
				func() {
					defer share.Unmount(ctx)
					if name == os.Getenv("SMB2_KRB5_ENCRYPTED_SHARE") {
						require.True(t, share.shareFlags&smb2.SMB2_SHAREFLAG_ENCRYPT_DATA != 0)
					}
					path := fmt.Sprintf("kerberos-test-%d.txt", time.Now().UnixNano())
					payload := []byte("Kerberos authenticated SMB read/write\n")
					require.NoError(t, share.WriteFile(ctx, path, payload, 0o600))
					defer share.Remove(ctx, path)
					got, err := share.ReadFile(ctx, path)
					require.NoError(t, err)
					require.Equal(t, payload, got)
				}()
			}
		})
	}
}
