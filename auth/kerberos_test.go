package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	krbclient "github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
)

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
	if _, err := c.NewInitiator(context.Background(), "one"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed credential: %v", err)
	}
	if _, err := first.InitSecContext(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("previously created initiator: %v", err)
	}
}

func TestKerberosCredentialConcurrentClose(t *testing.T) {
	c := &KerberosCredential{client: krbclient.NewWithPassword("user", "EXAMPLE.COM", "unused", config.New()), targetSPN: "cifs/override"}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			i, err := c.NewInitiator(context.Background(), "server")
			if err != nil && !errors.Is(err, os.ErrClosed) {
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

func TestKerberosOptionsValidation(t *testing.T) {
	for _, options := range []KerberosOptions{
		{}, {ConfigFile: "unused"},
		{ConfigFile: "unused", User: "u", Password: "p", KeytabFile: "keytab"},
		{ConfigFile: "unused", CCacheFile: "cache", User: "u"},
		{ConfigFile: "unused", CCacheFile: "cache", Realm: "R"},
		{ConfigFile: "unused", CCacheFile: "cache", Password: "p"},
		{ConfigFile: "unused", CCacheFile: "cache", KeytabFile: "keytab"},
	} {
		c, err := NewKerberosCredential(options)
		if err == nil || c != nil {
			if c != nil {
				c.Close()
			}
			t.Fatalf("invalid options accepted")
		}
	}
	cfg := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(cfg, []byte("[libdefaults]\n default_realm = EXAMPLE.COM\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, options := range []KerberosOptions{
		{ConfigFile: cfg + "missing", User: "user", Password: "unused"},
		{ConfigFile: cfg, User: "user", KeytabFile: cfg + "missing"},
		{ConfigFile: cfg, CCacheFile: cfg + "missing"},
	} {
		c, err := NewKerberosCredential(options)
		if err == nil || c != nil {
			if c != nil {
				c.Close()
			}
			t.Fatal("missing configuration or credentials accepted")
		}
	}
}
