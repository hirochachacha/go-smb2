package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	krbclient "github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/keytab"
)

// KerberosOptions configures Kerberos authentication without exposing library
// types. ConfigFile is required. Use Password, KeytabFile, or CCacheFile;
// these credential sources are mutually exclusive.
type KerberosOptions struct {
	User       string
	Realm      string // Empty uses the default realm in ConfigFile.
	Password   string
	ConfigFile string
	KeytabFile string
	CCacheFile string // File cache; identity comes from the cache, not User/Realm.
	TargetSPN  string // Empty uses cifs/<server> for each new initiator.
}

// KerberosCredential owns a Kerberos client and its ticket cache. Create it
// with NewKerberosCredential, share it across dialers, and close it when no
// longer needed. It is safe for concurrent use and must not be copied.
type KerberosCredential struct {
	mu        sync.Mutex
	client    *krbclient.Client
	targetSPN string
	closed    bool
}

// NewKerberosCredential loads configuration and credentials and authenticates
// to the KDC. Password/keytab credentials renew tickets internally; file-cache
// credentials use the cache's existing ticket lifetime. KDC exchanges use the
// underlying client's timeouts and cannot be canceled by a context.
func NewKerberosCredential(options KerberosOptions) (*KerberosCredential, error) {
	if options.ConfigFile == "" {
		return nil, errors.New("kerberos: ConfigFile is required")
	}
	if (options.KeytabFile != "" && options.Password != "") || (options.CCacheFile != "" && (options.KeytabFile != "" || options.Password != "" || options.User != "" || options.Realm != "")) {
		return nil, errors.New("kerberos: conflicting credential sources or cache identity")
	}
	if options.CCacheFile == "" && options.User == "" {
		return nil, errors.New("kerberos: User is required")
	}
	cfg, err := config.Load(options.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("kerberos: load configuration: %v", err)
	}
	var cl *krbclient.Client
	switch {
	case options.CCacheFile != "":
		cache, err := credentials.LoadCCache(options.CCacheFile)
		if err != nil {
			return nil, fmt.Errorf("kerberos: load credential cache: %v", err)
		}
		cl, err = krbclient.NewFromCCache(cache, cfg)
		if err != nil {
			if cl != nil {
				cl.Destroy()
			}
			return nil, fmt.Errorf("kerberos: initialize credential cache: %v", err)
		}
	case options.KeytabFile != "":
		kt, err := keytab.Load(options.KeytabFile)
		if err != nil {
			return nil, fmt.Errorf("kerberos: load keytab: %v", err)
		}
		cl = krbclient.NewWithKeytab(options.User, options.Realm, kt, cfg)
	default:
		cl = krbclient.NewWithPassword(options.User, options.Realm, options.Password, cfg)
	}
	if err := cl.Login(); err != nil {
		cl.Destroy()
		return nil, fmt.Errorf("kerberos: login: %v", err)
	}
	return &KerberosCredential{client: cl, targetSPN: options.TargetSPN}, nil
}

// NewInitiator creates independent handshake state while sharing the ticket
// cache. Context cancellation is checked here but cannot interrupt KDC I/O.
func (c *KerberosCredential) NewInitiator(ctx context.Context, serverName string) (Initiator, error) {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil {
		return nil, os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, os.ErrClosed
	}
	if c.client == nil {
		return nil, os.ErrInvalid
	}
	spn := c.targetSPN
	if spn == "" {
		spn = "cifs/" + serverName
	}
	return &kerberosInitiator{Client: c.client, TargetSPN: spn, owner: c}, nil
}

// Close stops ticket renewal and releases the cache. It is idempotent and
// waits for active ticket acquisition to finish. It does not close SMB sessions.
func (c *KerberosCredential) Close() error {
	if c == nil {
		return os.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.client != nil {
		c.client.Destroy()
		c.client = nil
	}
	return nil
}
