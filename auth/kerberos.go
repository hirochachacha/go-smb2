package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	krbclient "github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/keytab"
)

// KerberosConfig configures one Kerberos authentication method. Use
// KerberosPassword, KerberosKeytab, or KerberosCCache, as a value or pointer.
type KerberosConfig interface {
	configureKerberos(*kerberosConfig)
}

type kerberosConfig struct {
	configFile   string
	targetSPN    *string
	createClient func(*config.Config) (*krbclient.Client, error)
}

// KerberosPassword configures password authentication.
// The underlying Kerberos client currently rejects empty passwords.
type KerberosPassword struct {
	ConfigFile string // Required Kerberos configuration file.
	User       string
	Realm      string // Empty uses the default realm in ConfigFile.
	Password   string
	// TargetSPN defaults to cifs/<server> when nil. An explicit empty SPN is invalid.
	TargetSPN *string
}

func (c KerberosPassword) configureKerberos(cfg *kerberosConfig) {
	cfg.configFile, cfg.targetSPN, cfg.createClient = c.ConfigFile, c.TargetSPN, c.createClient
}

// KerberosKeytab configures keytab authentication.
type KerberosKeytab struct {
	ConfigFile string // Required Kerberos configuration file.
	User       string
	Realm      string // Empty uses the default realm in ConfigFile.
	File       string // Required keytab file.
	// TargetSPN defaults to cifs/<server> when nil. An explicit empty SPN is invalid.
	TargetSPN *string
}

func (c KerberosKeytab) configureKerberos(cfg *kerberosConfig) {
	cfg.configFile, cfg.targetSPN, cfg.createClient = c.ConfigFile, c.TargetSPN, c.createClient
}

// KerberosCCache configures authentication using an existing credential cache.
// The cache supplies the identity, and its tickets retain their existing lifetime.
type KerberosCCache struct {
	ConfigFile string // Required Kerberos configuration file.
	File       string // Required credential cache file.
	// TargetSPN defaults to cifs/<server> when nil. An explicit empty SPN is invalid.
	TargetSPN *string
}

func (c KerberosCCache) configureKerberos(cfg *kerberosConfig) {
	cfg.configFile, cfg.targetSPN, cfg.createClient = c.ConfigFile, c.TargetSPN, c.createClient
}

func (c KerberosPassword) createClient(cfg *config.Config) (*krbclient.Client, error) {
	if c.User == "" {
		return nil, errors.New("kerberos: User is required")
	}
	realm := c.Realm
	if realm == "" {
		realm = cfg.LibDefaults.DefaultRealm
	}
	return krbclient.NewWithPassword(c.User, realm, c.Password, cfg), nil
}

func (c KerberosKeytab) createClient(cfg *config.Config) (*krbclient.Client, error) {
	if c.User == "" || c.File == "" {
		return nil, errors.New("kerberos: keytab User and File are required")
	}
	kt, err := keytab.Load(c.File)
	if err != nil {
		return nil, fmt.Errorf("kerberos: load keytab: %v", err)
	}
	realm := c.Realm
	if realm == "" {
		realm = cfg.LibDefaults.DefaultRealm
	}
	return krbclient.NewWithKeytab(c.User, realm, kt, cfg), nil
}

func (c KerberosCCache) createClient(cfg *config.Config) (*krbclient.Client, error) {
	if c.File == "" {
		return nil, errors.New("kerberos: cache File is required")
	}
	cache, err := credentials.LoadCCache(c.File)
	if err != nil {
		return nil, fmt.Errorf("kerberos: load credential cache: %v", err)
	}
	cl, err := krbclient.NewFromCCache(cache, cfg)
	if err != nil {
		if cl != nil {
			cl.Destroy()
		}
		return nil, fmt.Errorf("kerberos: initialize credential cache: %v", err)
	}
	return cl, nil
}

// KerberosCredential owns a logged-in Kerberos client and its ticket cache.
// Create it with NewKerberosCredential and call Close after all uses. It is safe
// for concurrent use and must not be copied.
type KerberosCredential struct {
	mu        sync.Mutex
	client    *krbclient.Client
	targetSPN string
	closed    bool
}

// NewKerberosCredential loads configuration and credentials and logs in to the
// KDC. Password/keytab credentials renew tickets internally; file-cache tickets
// retain their existing lifetime. KDC I/O uses the underlying client's timeouts.
// The configuration is copied; the returned credential owns all runtime resources.
func NewKerberosCredential(settings KerberosConfig) (*KerberosCredential, error) {
	// Normalize pointers without invoking value-receiver methods on typed nils.
	switch value := settings.(type) {
	case *KerberosPassword:
		settings = nil
		if value != nil {
			settings = *value
		}
	case *KerberosKeytab:
		settings = nil
		if value != nil {
			settings = *value
		}
	case *KerberosCCache:
		settings = nil
		if value != nil {
			settings = *value
		}
	}
	var resolved kerberosConfig
	switch settings.(type) {
	case KerberosPassword, KerberosKeytab, KerberosCCache:
		settings.configureKerberos(&resolved)
	default:
		return nil, errInvalidCredential
	}
	if resolved.configFile == "" {
		return nil, errors.New("kerberos: ConfigFile is required")
	}
	spn := ""
	if resolved.targetSPN != nil {
		spn = *resolved.targetSPN
		if spn == "" {
			return nil, errors.New("kerberos: TargetSPN must not be empty")
		}
	}
	cfg, err := config.Load(resolved.configFile)
	if err != nil {
		return nil, fmt.Errorf("kerberos: load configuration: %v", err)
	}
	cl, err := resolved.createClient(cfg)
	if err != nil {
		return nil, err
	}
	if err := cl.Login(); err != nil {
		cl.Destroy()
		return nil, fmt.Errorf("kerberos: login: %v", err)
	}
	return &KerberosCredential{client: cl, targetSPN: spn}, nil
}

// NewInitiator creates independent handshake state while sharing the ticket
// cache. Context cancellation is checked here but cannot interrupt KDC I/O.
func (c *KerberosCredential) NewInitiator(ctx context.Context, serverName string) (Initiator, error) {
	if ctx == nil {
		panic("nil context")
	}
	if c == nil {
		return nil, errInvalidCredential
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errCredentialClosed
	}
	if c.client == nil {
		return nil, errInvalidCredential
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
		return errInvalidCredential
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
