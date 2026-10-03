package auth

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	krbclient "github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	"github.com/stretchr/testify/require"
)

func TestKerberosCredentialRealmSelection(t *testing.T) {
	for _, source := range []string{"password", "keytab"} {
		for _, realm := range []string{"", "OVERRIDE.COM"} {
			t.Run(source+"/realm="+realm, func(t *testing.T) {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer listener.Close()
				dir := t.TempDir()
				cfg := filepath.Join(dir, "krb5.conf")
				configuration := fmt.Sprintf("[libdefaults]\n default_realm = EXAMPLE.COM\n dns_lookup_kdc = false\n udp_preference_limit = 1\n[realms]\n EXAMPLE.COM = {\n kdc = %s\n }\n OVERRIDE.COM = {\n kdc = %s\n }\n", listener.Addr(), listener.Addr())
				require.NoError(t, os.WriteFile(cfg, []byte(configuration), 0600))
				var settings KerberosConfig
				wantRealm := realm
				if wantRealm == "" {
					wantRealm = "EXAMPLE.COM"
				}
				if source == "password" {
					settings = KerberosPassword{ConfigFile: cfg, User: "synthetic-user", Realm: realm, Password: "synthetic-password"}
				} else {
					kt := keytab.New()
					require.NoError(t, kt.AddEntry("synthetic-user", wantRealm, "synthetic-password", time.Now(), 1, etypeID.AES128_CTS_HMAC_SHA1_96))
					data, err := kt.Marshal()
					require.NoError(t, err)
					keytabFile := filepath.Join(dir, "keytab")
					settings = KerberosKeytab{ConfigFile: cfg, User: "synthetic-user", Realm: realm, File: keytabFile}
					require.NoError(t, os.WriteFile(keytabFile, data, 0600))
				}
				type result struct {
					request messages.ASReq
					err     error
				}
				done := make(chan result, 1)
				go func() {
					request, err := receiveTestASReq(listener)
					done <- result{request, err}
				}()
				credential, loginErr := NewKerberosCredential(settings)
				if credential != nil {
					credential.Close()
				}
				listener.Close() // Unblock Accept if login failed before sending.
				got := <-done
				require.NoError(t, got.err, "login returned %v before the fake KDC received an AS-REQ", loginErr)
				require.Nil(t, credential)
				require.Error(t, loginErr, "the fake KDC rejects the synthetic principal")
				require.Equal(t, wantRealm, got.request.ReqBody.Realm)
				require.Equal(t, []string{"synthetic-user"}, got.request.ReqBody.CName.NameString)
				require.Equal(t, []string{"krbtgt", wantRealm}, got.request.ReqBody.SName.NameString)
			})
		}
	}
}

// receiveTestASReq captures the actual selected realm and rejects the synthetic
// principal so the test needs neither real credentials nor a successful login.
func receiveTestASReq(listener net.Listener) (request messages.ASReq, err error) {
	conn, err := listener.Accept()
	if err != nil {
		return request, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return request, err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return request, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 1<<20 {
		return request, fmt.Errorf("unexpected AS-REQ size %d", length)
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(conn, data); err != nil {
		return request, err
	}
	if err := request.Unmarshal(data); err != nil {
		return request, err
	}
	response := messages.NewKRBError(request.ReqBody.SName, request.ReqBody.Realm, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "synthetic principal")
	data, err = response.Marshal()
	if err != nil {
		return request, err
	}
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	_, err = io.Copy(conn, io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(data)))
	return request, err
}

func TestKerberosCredentialWithoutDefaultRealm(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "krb5.conf")
	require.NoError(t, os.WriteFile(cfg, []byte("[libdefaults]\n dns_lookup_kdc = false\n"), 0600))
	kt := keytab.New()
	require.NoError(t, kt.AddEntry("synthetic-user", "EXAMPLE.COM", "synthetic-password", time.Now(), 1, etypeID.AES128_CTS_HMAC_SHA1_96))
	data, err := kt.Marshal()
	require.NoError(t, err)
	ktFile := filepath.Join(dir, "keytab")
	require.NoError(t, os.WriteFile(ktFile, data, 0600))
	for _, settings := range []KerberosConfig{
		&KerberosPassword{ConfigFile: cfg, User: "synthetic-user", Password: "synthetic-password"},
		&KerberosKeytab{ConfigFile: cfg, User: "synthetic-user", File: ktFile},
	} {
		credential, err := NewKerberosCredential(settings)
		require.Nil(t, credential)
		require.ErrorContains(t, err, "realm")
	}
}

func TestKerberosCredentialCacheIdentity(t *testing.T) {
	const realm = "CACHE.COM"
	user := types.PrincipalName{NameType: 1, NameString: []string{"cached-user"}}
	server := types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", realm}}
	ticket := messages.Ticket{TktVNO: 5, Realm: realm, SName: server, EncPart: types.EncryptedData{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Cipher: []byte("synthetic-ticket")}}
	ticketData, err := ticket.Marshal()
	require.NoError(t, err)
	now := time.Now().Add(-time.Minute)
	cache := credentials.NewV4CCache()
	cache.SetDefaultPrincipal(credentials.NewPrincipal(user, realm))
	cache.AddCredential(&credentials.Credential{
		Client: credentials.NewPrincipal(user, realm), Server: credentials.NewPrincipal(server, realm),
		Key:      types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)},
		AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), RenewTill: now.Add(2 * time.Hour),
		TicketFlags: types.NewKrbFlags(), Ticket: ticketData,
	})
	data, err := cache.Marshal()
	require.NoError(t, err)
	dir := t.TempDir()
	cacheFile := filepath.Join(dir, "ccache")
	require.NoError(t, os.WriteFile(cacheFile, data, 0600))
	for _, defaultRealm := range []string{"EXAMPLE.COM", ""} {
		t.Run("default="+defaultRealm, func(t *testing.T) {
			cfg := filepath.Join(t.TempDir(), "krb5.conf")
			configuration := "[libdefaults]\n dns_lookup_kdc = false\n"
			if defaultRealm != "" {
				configuration += " default_realm = " + defaultRealm + "\n"
			}
			require.NoError(t, os.WriteFile(cfg, []byte(configuration), 0600))
			settings := KerberosCCache{ConfigFile: cfg, File: cacheFile}
			wantSPN := "cifs/server"
			if defaultRealm == "" {
				settings.TargetSPN = new("cifs/override")
				wantSPN = "cifs/override"
			}
			credential, err := NewKerberosCredential(settings)
			require.NoError(t, err)
			defer credential.Close()
			if settings.TargetSPN != nil {
				*settings.TargetSPN = "cifs/changed"
			}
			var wg sync.WaitGroup
			initiators := make([]Initiator, 16)
			errs := make([]error, 16)
			for n := range initiators {
				wg.Go(func() { initiators[n], errs[n] = credential.NewInitiator(context.Background(), "server") })
			}
			wg.Wait()
			for n, initiator := range initiators {
				require.NoError(t, errs[n])
				got := initiator.(*kerberosInitiator)
				require.Equal(t, realm, got.Client.Credentials.Domain())
				require.Equal(t, "cached-user", got.Client.Credentials.UserName())
				require.Equal(t, wantSPN, got.TargetSPN)
				require.Same(t, initiators[0].(*kerberosInitiator).Client, got.Client)
				if n > 0 {
					require.NotSame(t, initiators[0], initiator)
				}
			}
		})
	}
}

func TestKerberosCredentialLifecycle(t *testing.T) {
	cl := krbclient.NewWithPassword("user", "EXAMPLE.COM", "unused", config.New())
	c := &KerberosCredential{client: cl}
	first, err := c.NewInitiator(context.Background(), "one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.NewInitiator(context.Background(), "two")
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.(*kerberosInitiator), second.(*kerberosInitiator)
	if a == b || a.Client != cl || b.Client != cl || a.TargetSPN != "cifs/one" || b.TargetSPN != "cifs/two" {
		t.Fatal("initiators must share tickets but not handshake state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.NewInitiator(ctx, "three"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.NewInitiator(context.Background(), "one"); !errors.Is(err, errCredentialClosed) || errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed credential: %v", err)
	}
	if _, err := first.InitSecContext(); !errors.Is(err, errCredentialClosed) || errors.Is(err, os.ErrClosed) {
		t.Fatalf("previously created initiator: %v", err)
	}
}

func TestKerberosCredentialConcurrentClose(t *testing.T) {
	c := &KerberosCredential{client: krbclient.NewWithPassword("user", "EXAMPLE.COM", "unused", config.New()), targetSPN: "cifs/override"}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			i, err := c.NewInitiator(context.Background(), "server")
			if err != nil && (!errors.Is(err, errCredentialClosed) || errors.Is(err, os.ErrClosed)) {
				t.Errorf("NewInitiator: %v", err)
			}
			if err == nil && i.(*kerberosInitiator).TargetSPN != "cifs/override" {
				t.Error("SPN override was lost")
			}
			if err := c.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
	wg.Wait()
}

func TestKerberosCredentialsValidation(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(cfg, []byte("[libdefaults]\n default_realm = EXAMPLE.COM\n"), 0600))
	for _, settings := range []KerberosConfig{
		&KerberosPassword{}, &KerberosKeytab{}, &KerberosCCache{},
		&KerberosPassword{ConfigFile: cfg},
		&KerberosKeytab{ConfigFile: cfg, User: "u"},
		&KerberosCCache{ConfigFile: cfg},
		(*KerberosPassword)(nil), (*KerberosKeytab)(nil), (*KerberosCCache)(nil),
		&KerberosPassword{ConfigFile: cfg, User: "u", TargetSPN: new("")},
		&KerberosKeytab{ConfigFile: cfg, User: "u", File: "unused", TargetSPN: new("")},
		&KerberosCCache{ConfigFile: cfg, File: "unused", TargetSPN: new("")},
		&KerberosPassword{ConfigFile: cfg + "missing", User: "user", Password: "unused"},
		&KerberosKeytab{ConfigFile: cfg, User: "user", File: cfg + "missing"},
		&KerberosCCache{ConfigFile: cfg, File: cfg + "missing"},
	} {
		credential, err := NewKerberosCredential(settings)
		require.Error(t, err)
		require.Nil(t, credential)
	}
}

func TestKerberosPasswordEmptyValue(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(cfg, []byte("[libdefaults]\n default_realm = EXAMPLE.COM\n"), 0600))
	credential, err := NewKerberosCredential(KerberosPassword{ConfigFile: cfg, User: "user", Password: ""})
	require.Nil(t, credential)
	require.ErrorContains(t, err, "kerberos: login:")
	require.ErrorContains(t, err, "neither a keytab nor a password")
}

func TestKerberosConfigTypes(t *testing.T) {
	for _, settings := range []KerberosConfig{KerberosPassword{}, KerberosKeytab{}, KerberosCCache{}} {
		_, ownsResources := settings.(interface{ Close() error })
		require.False(t, ownsResources, "configuration must not own resources")
	}
	credential, err := NewKerberosCredential(nil)
	require.Nil(t, credential)
	require.Error(t, err)
}
