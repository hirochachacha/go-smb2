// This package is used for integration testing.

package smb2_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"maps"
	"net"
	"os"
	"os/signal"
	"path"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"
	smbclient "github.com/hirochachacha/go-smb2/v2/client"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/notify"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

type transportDialerFunc func(ctx context.Context, serverName string) (smb2.Transport, error)

func (f transportDialerFunc) Dial(ctx context.Context, serverName string) (smb2.Transport, error) {
	return f(ctx, serverName)
}

func join(ss ...string) string {
	return strings.Join(ss, `\`)
}

type transportConfig struct {
	Type string              `json:"type"`
	Host string              `json:"host"`
	Port int                 `json:"port"`
	TLS  *transportTLSConfig `json:"tls"`
}

type transportTLSConfig struct {
	ServerName string `json:"server_name"`
	CAFile     string `json:"ca_file"`
}

type connConfig struct {
	RequireMessageSigning bool   `json:"signing"`
	ClientGuid            string `json:"guid"`
	SpecifiedDialect      uint16 `json:"dialect"`
}

type sessionConfig struct {
	Type        string `json:"type"`
	User        string `json:"user"`
	Password    string `json:"passwd"`
	Domain      string `json:"domain"`
	Workstation string `json:"workstation"`
	Realm       string `json:"realm"`
	KRB5Config  string `json:"krb5Config"`
	TargetSPN   string `json:"targetSPN"`
}

type treeConnConfig struct {
	Share1 string `json:"share1"`
	Share2 string `json:"share2"`
}

// kerberosConfig selects the dialect matrix test. TreeConn.Share1 must be
// writable without encryption; EncryptedShare must require SMB encryption.
type kerberosConfig struct {
	EncryptedShare string `json:"encrypted_share"`
}

type dfsConfig struct {
	Target       string `json:"target"`
	SecondTarget string `json:"second_target"`
	Link         string `json:"link"`
}

type config struct {
	Name             string          `json:"name"`
	DFS              *dfsConfig      `json:"dfs"`
	Kerberos         *kerberosConfig `json:"kerberos"`
	MaxCreditBalance uint16          `json:"max_credit_balance"`
	Transport        transportConfig `json:"transport"`
	Conn             connConfig      `json:"conn"`
	Session          sessionConfig   `json:"session"`
	TreeConn         treeConnConfig  `json:"tree_conn"`
}

// env holds the connection established from a single client_conf.json entry.
type env struct {
	cfg                config
	dialer             *smb2.Dialer
	fs                 *smb2.Share
	rfs                *smb2.Share
	session            *smb2.Session
	destroyCredentials func()
}

var (
	envs                   []*env
	dfsEnv                 *config
	kerberosEnvs           []config
	integrationInterrupted atomic.Bool
)

// loadEnvs saves specialized test configurations and connects to ordinary
// test entries. Unreachable environments are skipped.
func loadEnvs() []*env {
	configPath := os.Getenv("SMB2_CLIENT_CONFIG")
	if configPath == "" {
		configPath = "client_conf.json"
	}

	cf, err := os.Open(configPath)
	if err != nil {
		fmt.Printf("cannot open %s\n", configPath)
		return nil
	}
	defer cf.Close()

	var cfgs []config
	if err := json.NewDecoder(cf).Decode(&cfgs); err != nil {
		fmt.Printf("cannot decode %s\n", configPath)
		return nil
	}

	var es []*env
	for _, cfg := range cfgs {
		if integrationInterrupted.Load() {
			break
		}
		if cfg.DFS != nil {
			dfsEnv = &cfg
			continue
		}
		if cfg.Kerberos != nil {
			kerberosEnvs = append(kerberosEnvs, cfg)
			continue
		}
		if e := connect(cfg); e != nil {
			es = append(es, e)
		}
	}
	return es
}

func connect(cfg config) *env {
	if cfg.Transport.Type != "tcp" && cfg.Transport.Type != "quic" {
		fmt.Println("unsupported transport type")
		return nil
	}

	var tlsConfig *tls.Config
	if cfg.Transport.Type == "quic" && cfg.Transport.TLS != nil {
		tlsConfig = &tls.Config{ServerName: cfg.Transport.TLS.ServerName}
		if path := cfg.Transport.TLS.CAFile; path != "" {
			pem, err := os.ReadFile(path)
			if err != nil {
				panic(fmt.Errorf("%s: read QUIC CA file: %w", cfg.Name, err))
			}
			tlsConfig.RootCAs = x509.NewCertPool()
			if !tlsConfig.RootCAs.AppendCertsFromPEM(pem) {
				panic(fmt.Errorf("%s: QUIC CA file %q contains no certificates", cfg.Name, path))
			}
		}
	}

	var credentials smb2.Credentials
	var destroyCredentials func()
	switch cfg.Session.Type {
	case "ntlm":
		credentials = auth.NTLMCredential{
			User:        cfg.Session.User,
			Password:    cfg.Session.Password,
			Domain:      cfg.Session.Domain,
			Workstation: cfg.Session.Workstation,
			TargetSPN:   cfg.Session.TargetSPN,
		}
	case "kerberos":
		kerberos, err := auth.NewKerberosCredential(auth.KerberosOptions{
			User: cfg.Session.User, Realm: cfg.Session.Realm, Password: cfg.Session.Password,
			ConfigFile: cfg.Session.KRB5Config, TargetSPN: cfg.Session.TargetSPN,
		})
		if err != nil {
			panic(err)
		}
		credentials = kerberos
		destroyCredentials = func() { _ = kerberos.Close() }
	default:
		panic(fmt.Sprintf("unsupported session type %q", cfg.Session.Type))
	}

	dialer := &smb2.Dialer{
		Credentials: credentials,
		TransportDialer: transportDialerFunc(func(ctx context.Context, _ string) (smb2.Transport, error) {
			addr := net.JoinHostPort(cfg.Transport.Host, strconv.Itoa(cfg.Transport.Port))
			if cfg.Transport.Type == "quic" {
				return smb2.QUICDialer{Port: cfg.Transport.Port, TLSConfig: tlsConfig}.Dial(ctx, cfg.Transport.Host)
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			return smb2.NewTransport(conn), nil
		}),
		MaxCreditBalance:      cfg.MaxCreditBalance,
		RequireMessageSigning: cfg.Conn.RequireMessageSigning,
		SpecifiedDialects: func() []smb2.Dialect {
			if cfg.Conn.SpecifiedDialect != 0 {
				return []smb2.Dialect{smb2.Dialect(cfg.Conn.SpecifiedDialect)}
			}
			return nil
		}(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := dialer.Dial(ctx, cfg.Transport.Host)
	if err != nil {
		if destroyCredentials != nil {
			destroyCredentials()
		}
		fmt.Printf("skipping %s: connection failed: %v\n", cfg.Name, err)
		return nil
	}
	fs1, err := session.Mount(ctx, cfg.TreeConn.Share1)
	if err != nil {
		session.Close()
		if destroyCredentials != nil {
			destroyCredentials()
		}
		panic(err)
	}

	fs2, err := session.Mount(ctx, cfg.TreeConn.Share2)
	if err != nil {
		fs1.Unmount(ctx)
		session.Close()
		if destroyCredentials != nil {
			destroyCredentials()
		}
		panic(err)
	}

	return &env{
		cfg:                cfg,
		dialer:             dialer,
		fs:                 fs1,
		rfs:                fs2,
		session:            session,
		destroyCredentials: destroyCredentials,
	}
}

func (e *env) close() {
	e.rfs.Unmount(context.Background())
	e.fs.Unmount(context.Background())
	e.session.Close()
	if e.destroyCredentials != nil {
		e.destroyCredentials()
	}
}

// forEachEnv runs tests in parallel, with each test's environments run serially.
func forEachEnv(t *testing.T, f func(t *testing.T, e *env)) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if len(envs) == 0 {
		t.Skip("client_conf.json is not configured")
	}
	t.Parallel()
	for _, e := range envs {
		t.Run(e.cfg.Name, func(t *testing.T) {
			if integrationInterrupted.Load() {
				t.Skip("integration tests interrupted")
			}
			f(t, e)
		})
	}
}

// newTestDirectory creates a directory owned by this subtest. Cleanup runs
// after deferred file closes and reports failures instead of silently leaking it.
func newTestDirectory(t *testing.T, fs *smb2.Share) string {
	t.Helper()
	name, _, _ := strings.Cut(t.Name(), "/")
	dir := "go-smb2-" + name + "-" + rand.Text()
	require.NoError(t, fs.Mkdir(context.Background(), dir, 0o755))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := fs.RemoveAll(ctx, dir); err != nil {
			t.Errorf("remove test directory %q: %v", dir, err)
		}
	})
	return dir
}

func TestMain(m *testing.M) {
	flag.Parse()
	interrupts := make(chan os.Signal, 1)
	finished := make(chan struct{})
	if !testing.Short() {
		signal.Notify(interrupts, os.Interrupt)
		go func() {
			select {
			case <-interrupts:
				integrationInterrupted.Store(true)
				signal.Stop(interrupts)
				fmt.Fprintln(os.Stderr, "Interrupted: waiting for running tests and cleanup; press Ctrl-C again to force exit.")
			case <-finished:
			}
		}()
		envs = loadEnvs()
	}
	code := m.Run()
	for _, e := range envs {
		e.close()
	}
	close(finished)
	signal.Stop(interrupts)
	if integrationInterrupted.Load() {
		code = 130
	}
	os.Exit(code)
}

func TestMkdirPreservesReadOnlyPermission(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)
		readOnlyDir := join(testDir, "readOnly")
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := fs.Chmod(ctx, readOnlyDir, 0o755); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("restore directory permissions: %v", err)
			}
		})

		if err := fs.Mkdir(context.Background(), readOnlyDir, 0o444); err != nil {
			t.Fatal(err)
		}

		info, err := fs.Stat(context.Background(), readOnlyDir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o200 != 0 {
			t.Errorf("read-only directory mode = %o, has owner write permission", info.Mode().Perm())
		}
	})
}

func TestReaddir(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		d, err := fs.Open(context.Background(), testDir)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close(context.Background())

		fi, err := d.Readdir(context.Background(), -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(fi) != 0 {
			t.Error("unexpected content length:", len(fi))
		}

		f, err := fs.Create(context.Background(), testDir+`\testFile`)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.Remove(context.Background(), testDir+`\testFile`)
		defer f.Close(context.Background())

		d2, err := fs.Open(context.Background(), testDir)
		if err != nil {
			t.Fatal(err)
		}
		defer d2.Close(context.Background())

		fi2, err := d2.Readdir(context.Background(), -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(fi2) != 1 {
			t.Error("unexpected content length:", len(fi2))
		}

		_, err = d2.Readdir(context.Background(), 1)
		if err != io.EOF {
			t.Error("unexpected error: ", err)
		}
	})
}

func TestFile(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		f, err := fs.Create(context.Background(), testDir+`\testFile`)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.Remove(context.Background(), testDir+`\testFile`)
		defer f.Close(context.Background())

		if f.Name() != testDir+`\testFile` {
			t.Error("unexpected name:", f.Name())
		}

		n, err := f.Write(context.Background(), []byte("test"))
		if err != nil {
			t.Fatal(err)
		}

		if n != 4 {
			t.Error("unexpected content length:", n)
		}

		n, err = f.Write(context.Background(), []byte("Content"))
		if err != nil {
			t.Fatal(err)
		}

		if n != 7 {
			t.Error("unexpected content length:", n)
		}

		n64, err := f.Seek(context.Background(), 0, io.SeekStart)
		if err != nil {
			t.Fatal(err)
		}

		if n64 != 0 {
			t.Error("unexpected seek length:", n64)
		}

		p := make([]byte, 10)

		n, err = f.Read(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}

		if n != 10 {
			t.Error("unexpected content length:", n)
		}

		if string(p) != "testConten" {
			t.Error("unexpected content:", string(p))
		}

		stat, err := f.Stat(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		if stat.Name() != "testFile" {
			t.Error("unexpected name:", stat.Name())
		}

		if stat.Size() != 11 {
			t.Error("unexpected content length:", n)
		}

		if stat.IsDir() {
			t.Error("should be not a directory")
		}

		f.Truncate(context.Background(), 4)

		n64, err = f.Seek(context.Background(), -3, io.SeekEnd)
		if err != nil {
			t.Fatal(err)
		}

		if n64 != 1 {
			t.Error("unexpected seek length:", n64)
		}

		n, err = f.Read(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}

		if n != 3 {
			t.Error("unexpected content length:", n)
		}

		if string(p[:n]) != "est" {
			t.Error("unexpected content:", string(p))
		}
	})
}

func skipPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) || errors.Is(err, erref.STATUS_PRIVILEGE_NOT_HELD) {
		t.Skipf("account lacks permission for this operation: %v", err)
	}
}

func TestSymlink(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		f, err := fs.Create(context.Background(), testDir+`\testFile`)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.Remove(context.Background(), testDir+`\testFile`)
		defer f.Close(context.Background())

		_, err = f.Write(context.Background(), []byte("testContent"))
		if err != nil {
			t.Fatal(err)
		}

		err = fs.Symlink(context.Background(), testDir+`\testFile`, testDir+`\linkToTestFile`)
		skipPermissionDenied(t, err)
		if err != nil {
			if errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
				t.Skip("symlink isn't supported")
			}
			t.Fatal(err)
		}
		defer fs.Remove(context.Background(), testDir+`\linkToTestFile`)

		stat, err := fs.Lstat(context.Background(), testDir+`\linkToTestFile`)
		if err != nil {
			t.Fatal(err)
		}

		if stat.Name() != `linkToTestFile` {
			t.Error("unexpected name:", stat.Name())
		}

		if stat.Mode()&os.ModeSymlink == 0 {
			t.Error("should be a symlink")
		}

		target, err := fs.Readlink(context.Background(), testDir+`\linkToTestFile`)
		if err != nil {
			t.Fatal(err)
		}

		if target != testDir+`\testFile` {
			t.Error("unexpected target:", target)
		}

		f, err = fs.Open(context.Background(), testDir+`\linkToTestFile`)
		if err == nil { // if it supports follow-symlink
			defer f.Close(context.Background())
			bs, err := io.ReadAll(f.WithContext(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			if string(bs) != "testContent" {
				t.Error("unexpected content:", string(bs))
			}

			stat, err := fs.Stat(context.Background(), testDir+`\linkToTestFile`)
			if err != nil {
				t.Fatal(err)
			}
			if stat.Size() != int64(len("testContent")) {
				t.Errorf("unexpected size: %d", stat.Size())
			}

			bs, err = fs.ReadFile(context.Background(), testDir+`\linkToTestFile`)
			if err != nil {
				t.Fatal(err)
			}
			if string(bs) != "testContent" {
				t.Errorf("unexpected content: %s", string(bs))
			}
		}
	})
}

func TestRelativeSymlink(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		f, err := fs.Create(context.Background(), testDir+`\target.txt`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(context.Background(), []byte("relativeSymlinkContent"))
		f.Close(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		err = fs.Symlink(context.Background(), "target.txt", testDir+`\linkToTarget`)
		skipPermissionDenied(t, err)
		if err != nil {
			if errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
				t.Skip("symlink isn't supported")
			}
			t.Fatal(err)
		}

		stat, err := fs.Lstat(context.Background(), testDir+`\linkToTarget`)
		if err != nil {
			t.Fatal(err)
		}

		if stat.Mode()&os.ModeSymlink == 0 {
			t.Error("should be a symlink")
		}

		target, err := fs.Readlink(context.Background(), testDir+`\linkToTarget`)
		if err != nil {
			t.Fatal(err)
		}

		if target != "target.txt" {
			t.Errorf("unexpected target: expected %q, got %q", "target.txt", target)
		}

		f, err = fs.Open(context.Background(), testDir+`\linkToTarget`)
		if err == nil { // if it supports follow-symlink
			defer f.Close(context.Background())
			bs, err := io.ReadAll(f.WithContext(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			if string(bs) != "relativeSymlinkContent" {
				t.Errorf("unexpected content: expected %q, got %q", "relativeSymlinkContent", string(bs))
			}

			stat, err := fs.Stat(context.Background(), testDir+`\linkToTarget`)
			if err != nil {
				t.Fatal(err)
			}
			if stat.Size() != int64(len("relativeSymlinkContent")) {
				t.Errorf("unexpected size: %d", stat.Size())
			}

			bs, err = fs.ReadFile(context.Background(), testDir+`\linkToTarget`)
			if err != nil {
				t.Fatal(err)
			}
			if string(bs) != "relativeSymlinkContent" {
				t.Errorf("unexpected content: %s", string(bs))
			}
		}
	})
}

func TestIsXXX(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		f, err := fs.Create(context.Background(), testDir+`\Exist`)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.Remove(context.Background(), testDir+`\Exist`)
		defer f.Close(context.Background())

		_, err = fs.OpenFile(context.Background(), testDir+`\Exist`, os.O_CREATE|os.O_EXCL, 0o666)
		if !errors.Is(err, os.ErrExist) {
			t.Error("unexpected error:", err)
		}
		if errors.Is(err, os.ErrNotExist) {
			t.Error("unexpected error:", err)
		}
		if errors.Is(err, os.ErrPermission) {
			t.Error("unexpected error:", err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Error("unexpected error:", err)
		}

		_, err = fs.Open(context.Background(), testDir+`\notExist`)
		if errors.Is(err, os.ErrExist) {
			t.Error("unexpected error:", err)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Error("unexpected error:", err)
		}
		if errors.Is(err, os.ErrPermission) {
			t.Error("unexpected error:", err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Error("unexpected error:", err)
		}

		err = fs.WriteFile(context.Background(), testDir+`\aaa`, []byte("aaa"), 0o444)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.WriteFile(context.Background(), testDir+`\aaa`, []byte("aaa"), 0o444)
		if !errors.Is(err, os.ErrPermission) {
			t.Error("unexpected error:", err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Error("unexpected error:", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		_, err = fs.Create(ctx, testDir+`\Exist`)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error("unexpected error:", err)
		}

		ctx, cancel = context.WithCancel(context.Background())
		cancel()
		_, err = fs.Create(ctx, testDir+`\Exist`)
		if errors.Is(err, context.DeadlineExceeded) {
			t.Error("unexpected error:", err)
		}
	})
}

func TestRename(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		f, err := fs.Create(context.Background(), testDir+`\old`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(context.Background(), []byte("testContent"))
		if err != nil {
			t.Fatal(err)
		}
		err = f.Close(context.Background())
		if err != nil {
			fs.Remove(context.Background(), testDir+`\old`)

			t.Fatal(err)
		}

		err = fs.Rename(context.Background(), testDir+`\old`, testDir+`\new`)
		if err != nil {
			fs.Remove(context.Background(), testDir+`\old`)

			t.Fatal(err)
		}
		defer fs.Remove(context.Background(), testDir+`\new`)

		_, err = fs.Stat(context.Background(), testDir+`\old`)
		if errors.Is(err, os.ErrExist) {
			t.Error("unexpected error:", err)
		}
		f, err = fs.Open(context.Background(), testDir+`\new`)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close(context.Background())
		bs, err := io.ReadAll(f.WithContext(context.Background()))
		if err != nil {
			t.Fatal(err)
		}
		if string(bs) != "testContent" {
			t.Error("unexpected content:", string(bs))
		}
	})
}

func TestChtimes(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		f, err := fs.Create(context.Background(), testDir+`\testFile`)
		if err != nil {
			t.Fatal(err)
		}
		err = f.Close(context.Background())
		if err != nil {
			fs.Remove(context.Background(), testDir+`\testFile`)

			t.Fatal(err)
		}

		atime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		if err != nil {
			t.Fatal(err)
		}
		mtime, err := time.Parse(time.RFC3339, "2006-03-08T19:32:05Z")
		if err != nil {
			t.Fatal(err)
		}

		err = fs.Chtimes(context.Background(), testDir+`\testFile`, atime, mtime)
		if err != nil {
			t.Fatal(err)
		}

		stat, err := fs.Stat(context.Background(), testDir+`\testFile`)
		if err != nil {
			t.Fatal(err)
		}

		if !stat.ModTime().Equal(mtime) {
			t.Error("unexpected mtime:", stat.ModTime())
		}
	})
}

func TestChmod(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		f, err := fs.Create(context.Background(), testDir+`\testFile`)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.Remove(context.Background(), testDir+`\testFile`)
		defer f.Close(context.Background())

		stat, err := f.Stat(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if stat.Mode() != 0o666 {
			t.Error("unexpected mode:", stat.Mode())
		}
		err = f.Chmod(context.Background(), 0o444)
		if err != nil {
			t.Fatal(err)
		}
		stat, err = f.Stat(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if stat.Mode() != 0o444 {
			t.Error("unexpected mode:", stat.Mode())
		}

		f2, err := fs.OpenFile(context.Background(), testDir+`\testReadOnlyFile`, os.O_CREATE, 0o000)
		if err != nil {
			t.Fatal(err)
		}
		f2.Close(context.Background())

		if err := fs.Chmod(context.Background(), testDir+`\testReadOnlyFile`, 0o444); err != nil {
			t.Fatal(err)
		}
		stat, err = fs.Stat(context.Background(), testDir+`\testReadOnlyFile`)
		if err != nil {
			t.Fatal(err)
		}
		if stat.Mode() != 0o444 {
			t.Error("unexpected mode:", stat.Mode())
		}
	})
}

func TestRemoveReadOnlyFile(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		f, err := fs.OpenFile(context.Background(), testDir+`\testReadOnlyFile`, os.O_CREATE, 0o000)
		if err != nil {
			t.Fatal(err)
		}
		f.Close(context.Background())

		if err := fs.Remove(context.Background(), testDir+`\testReadOnlyFile`); err != nil {
			t.Fatal(err)
		}
		if _, err := fs.Stat(context.Background(), testDir+`\testReadOnlyFile`); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("failed to delete read only file")
		}
	})
}

func TestOpenFileCreateExistingReadOnlyFile(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		name := pathpkg.Join(newTestDirectory(t, fs), "readOnlyFile")
		ctx := context.Background()
		content := []byte("existing content")

		require.NoError(t, fs.WriteFile(ctx, name, content, 0o666))
		require.NoError(t, fs.Chmod(ctx, name, 0o444))

		file, err := fs.OpenFile(ctx, name, os.O_RDONLY|os.O_CREATE, 0o666)
		require.NoError(t, err)
		require.NoError(t, file.Close(ctx))

		got, err := fs.ReadFile(ctx, name)
		require.NoError(t, err)
		require.Equal(t, content, got)

		info, err := fs.Stat(ctx, name)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o444), info.Mode().Perm())
	})
}

func TestListShareNames(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		cfg := e.cfg
		names, err := e.session.ListShareNames(context.Background())
		skipPermissionDenied(t, err)
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(names)
		for _, expected := range []string{"IPC$", cfg.TreeConn.Share1, cfg.TreeConn.Share2} {
			found := slices.Contains(names, expected)
			if !found {
				t.Errorf("couldn't find share name %s in %v", expected, names)
			}
		}
	})
}

// TestAppendIntegration exercises single-writer append semantics.
// Run against client_conf.json environments; -short skips it.
func TestAppendIntegration(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		dir := newTestDirectory(t, e.fs)
		for _, trunc := range []bool{false, true} {
			t.Run(fmt.Sprintf("write_truncate_%t", trunc), func(t *testing.T) {
				name := pathpkg.Join(dir, fmt.Sprintf("write-%t", trunc))
				require.NoError(t, e.fs.WriteFile(ctx, name, []byte("old"), 0o600))
				flags := os.O_RDWR | os.O_APPEND
				if trunc {
					flags |= os.O_TRUNC
				}
				f, err := e.fs.OpenFile(ctx, name, flags, 0o600)
				require.NoError(t, err)
				defer f.Close(context.Background())
				_, err = f.Write(ctx, []byte("A"))
				require.NoError(t, err)
				_, err = f.Write(ctx, []byte("B"))
				require.NoError(t, err)
				_, err = f.Write(ctx, []byte("C"))
				require.NoError(t, err)
				actual, err := e.fs.ReadFile(ctx, name)
				require.NoError(t, err)
				want := "ABC"
				if !trunc {
					want = "oldABC"
				}
				require.Equal(t, want, string(actual))
			})
		}
		t.Run("large_write", func(t *testing.T) {
			name := pathpkg.Join(dir, "large")
			require.NoError(t, e.fs.WriteFile(ctx, name, []byte("prefix"), 0o600))
			f, err := e.fs.OpenFile(ctx, name, os.O_WRONLY|os.O_APPEND, 0o600)
			require.NoError(t, err)
			defer f.Close(context.Background())
			payload := make([]byte, 3*1024*1024)
			for i := range payload {
				payload[i] = byte(i / 4096)
			}
			n, err := f.Write(ctx, payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			actual, err := e.fs.ReadFile(ctx, name)
			require.NoError(t, err)
			require.True(t, bytes.Equal(append([]byte("prefix"), payload...), actual), "large append lost or reordered bytes")
		})
		for _, readFrom := range []bool{false, true} {
			t.Run(fmt.Sprintf("copy_readfrom_%t", readFrom), func(t *testing.T) {
				source := pathpkg.Join(dir, fmt.Sprintf("source-%t", readFrom))
				dest := pathpkg.Join(dir, fmt.Sprintf("dest-%t", readFrom))
				payload := bytes.Repeat([]byte("copy"), 1024)
				require.NoError(t, e.fs.WriteFile(ctx, source, payload, 0o600))
				require.NoError(t, e.fs.WriteFile(ctx, dest, []byte("prefix"), 0o600))
				src, err := e.fs.Open(ctx, source)
				require.NoError(t, err)
				defer src.Close(context.Background())
				dst, err := e.fs.OpenFile(ctx, dest, os.O_RDWR|os.O_APPEND, 0o600)
				require.NoError(t, err)
				defer dst.Close(context.Background())
				var n int64
				if readFrom {
					n, err = dst.ReadFrom(ctx, src.WithContext(ctx))
				} else {
					n, err = src.WriteTo(ctx, dst.WithContext(ctx))
				}
				require.NoError(t, err)
				require.Equal(t, int64(len(payload)), n)
				actual, err := e.fs.ReadFile(ctx, dest)
				require.NoError(t, err)
				require.True(t, bytes.Equal(append([]byte("prefix"), payload...), actual), "copy did not append")
			})
		}
	})
}

// TestServerSideCopyOffsets covers the File API's choice between server-side copy
// and ordinary reads/writes, including the workaround for unequal offsets.
func TestServerSideCopyOffsets(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		dir := newTestDirectory(t, e.fs)
		const sourceText = "AAAABBBBCCCCDDDDEEEEFFFF"
		const destinationText = "0123456789abcdef"
		source := pathpkg.Join(dir, "source")
		require.NoError(t, e.fs.WriteFile(ctx, source, []byte(sourceText), 0o600))
		for _, readFrom := range []bool{false, true} {
			for _, tc := range []struct {
				name           string
				source, target int64
				appendMode     bool
			}{
				{"zero", 0, 0, false},
				{"equal", 4, 4, false},
				{"source", 4, 0, false},
				{"target", 0, 6, false},
				{"both", 4, 6, false},
				{"unaligned", 3, 5, false},
				{"extend", 8, 16, false},
				{"append_equal", 16, 16, true},
				{"append_different", 0, 16, true},
			} {
				t.Run(fmt.Sprintf("readFrom_%t_%s", readFrom, tc.name), func(t *testing.T) {
					name := pathpkg.Join(dir, fmt.Sprintf("dest-%t-%s", readFrom, tc.name))
					require.NoError(t, e.fs.WriteFile(ctx, name, []byte(destinationText), 0o600))
					src, err := e.fs.Open(ctx, source)
					require.NoError(t, err)
					defer src.Close(context.Background())
					flags := os.O_RDWR
					if tc.appendMode {
						flags |= os.O_APPEND
					}
					dst, err := e.fs.OpenFile(ctx, name, flags, 0o600)
					require.NoError(t, err)
					defer dst.Close(context.Background())
					_, err = src.Seek(ctx, tc.source, io.SeekStart)
					require.NoError(t, err)
					if !tc.appendMode {
						_, err = dst.Seek(ctx, tc.target, io.SeekStart)
						require.NoError(t, err)
					}
					var n int64
					if readFrom {
						n, err = dst.ReadFrom(ctx, src.WithContext(ctx))
					} else {
						n, err = src.WriteTo(ctx, dst.WithContext(ctx))
					}
					require.NoError(t, err)
					require.Equal(t, int64(len(sourceText))-tc.source, n)
					require.NoError(t, dst.Close(ctx))
					actual, err := e.fs.ReadFile(ctx, name)
					require.NoError(t, err)
					end := int(tc.target + n)
					expected := []byte(destinationText)
					if end > len(expected) {
						expected = append(expected, make([]byte, end-len(expected))...)
					}
					copy(expected[tc.target:], sourceText[tc.source:])
					require.Equal(t, string(expected), string(actual))
				})
			}
		}
	})
}

func TestServerSideCopy(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		err := fs.WriteFile(context.Background(), join(testDir, "src.txt"), []byte("hello world!"), 0o666)
		if err != nil {
			t.Fatal(err)
		}
		sf, err := fs.Open(context.Background(), join(testDir, "src.txt"))
		if err != nil {
			t.Fatal(err)
		}
		defer sf.Close(context.Background())

		df, err := fs.Create(context.Background(), join(testDir, "dst.txt"))
		if err != nil {
			t.Fatal(err)
		}
		defer df.Close(context.Background())

		_, err = io.Copy(df.WithContext(context.Background()), sf.WithContext(context.Background()))
		if err != nil {
			t.Error(err)
		}

		bs, err := fs.ReadFile(context.Background(), join(testDir, "dst.txt"))
		if err != nil {
			t.Fatal(err)
		}

		if string(bs) != "hello world!" {
			t.Error("unexpected content")
		}
	})
}

func TestRemoveAll(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)
		err := fs.WriteFile(context.Background(), join(testDir, "hello.txt"), []byte("hello world!"), 0o666)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.Mkdir(context.Background(), join(testDir, "hello"), 0o755)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.WriteFile(context.Background(), join(testDir, "hello", "hello.txt"), []byte("hello world!"), 0o444)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.RemoveAll(context.Background(), testDir)
		if err != nil {
			t.Error(err)
		}
	})
}

func TestRemoveAll_SymlinkNotFollowed(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)
		outsideDir := newTestDirectory(t, fs)
		secretFile := join(outsideDir, "secret.txt")
		err := fs.WriteFile(context.Background(), secretFile, []byte("preserve me"), 0o666)
		if err != nil {
			t.Fatal(err)
		}

		linkPath := join(testDir, "linkToOutside")
		err = fs.Symlink(context.Background(), outsideDir, linkPath)
		skipPermissionDenied(t, err)
		if err != nil {
			if errors.Is(err, erref.STATUS_NOT_SUPPORTED) {
				t.Skip("symlink isn't supported")
			}
			t.Fatal(err)
		}

		err = fs.RemoveAll(context.Background(), testDir)
		if err != nil {
			t.Fatalf("RemoveAll failed: %v", err)
		}

		// Ensure outside directory and file are still intact!
		bs, err := fs.ReadFile(context.Background(), secretFile)
		if err != nil {
			t.Fatalf("secretFile in outsideDir was deleted or unreadable: %v", err)
		}
		if string(bs) != "preserve me" {
			t.Fatalf("unexpected content in secretFile: %q", string(bs))
		}
	})
}

func TestContextCancellation(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		cfg := e.cfg
		ctx, cancel := context.WithCancel(context.Background())

		cancelShare, err := e.session.Mount(context.Background(), cfg.TreeConn.Share1)
		if err != nil {
			t.Fatal(err)
		}
		f, err := cancelShare.Open(context.Background(), ".")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close(context.Background())

		cancel()

		checkError1 := func(op string, err error) {
			if !errors.Is(err, context.Canceled) {
				t.Errorf("unexpected context handling: op=%s, type=%T, value=%v", op, err, err)
			}
		}

		checkError2 := checkError1

		_, err = e.session.Mount(ctx, "somewhere")
		checkError2("mount", err)

		err = cancelShare.Chmod(ctx, "aaa", 0)
		checkError2("chmod", err)
		err = cancelShare.Chtimes(ctx, "aaa", time.Time{}, time.Time{})
		checkError2("chtimes", err)
		_, err = cancelShare.Create(ctx, "aaa")
		checkError2("create", err)
		_, err = cancelShare.Lstat(ctx, "aaa")
		checkError2("lstat", err)
		err = cancelShare.Mkdir(ctx, "aaa", 0)
		checkError2("mkdir", err)
		err = cancelShare.MkdirAll(ctx, "aaa", 0)
		checkError2("mkdirall", err)
		_, err = cancelShare.Open(ctx, "aaa")
		checkError2("open", err)
		_, err = cancelShare.OpenFile(ctx, "aaa", 0, 0)
		checkError2("openfile", err)
		_, err = cancelShare.ReadDir(ctx, "aaa")
		checkError2("readdir", err)
		_, err = cancelShare.ReadFile(ctx, "aaa")
		checkError2("readfile", err)
		_, err = cancelShare.Readlink(ctx, "aaa")
		checkError2("readlink", err)
		err = cancelShare.Remove(ctx, "aaa")
		checkError2("remove", err)
		err = cancelShare.RemoveAll(ctx, "aaa")
		checkError2("removeall", err)
		err = cancelShare.Rename(ctx, "aaa", "bbb")
		checkError2("rename", err)
		_, err = cancelShare.Stat(ctx, "aaa")
		checkError2("stat", err)
		_, err = cancelShare.Statfs(ctx, "aaa")
		checkError2("statfs", err)
		err = cancelShare.Symlink(ctx, "aaa", "bbb")
		checkError2("symlink", err)
		err = cancelShare.Truncate(ctx, "aaa", 0)
		checkError2("truncate", err)
		err = cancelShare.WriteFile(ctx, "aaa", nil, 0)
		checkError2("writefile", err)
		err = cancelShare.Unmount(ctx)
		checkError1("umount", err)

		err = f.Chmod(ctx, 0)
		checkError2("fchmod", err)
		_, err = f.Read(ctx, make([]byte, 10))
		checkError2("fread", err)
		_, err = f.ReadAt(ctx, make([]byte, 10), 0)
		checkError2("freadat", err)
		_, err = f.ReadFrom(ctx, strings.NewReader("aaa"))
		checkError2("freadfrom", err)
		_, err = f.Readdir(ctx, -1)
		checkError2("freaddir", err)
		_, err = f.Readdirnames(ctx, -1)
		checkError2("freaddirnames", err)
		_, err = f.Seek(ctx, 1, io.SeekEnd)
		checkError2("fseek", err)
		_, err = f.Stat(ctx)
		checkError2("fstat", err)
		_, err = f.Statfs(ctx)
		checkError2("fstatfs", err)
		err = f.Sync(ctx)
		checkError2("fsync", err)
		err = f.Truncate(ctx, 1)
		checkError2("ftruncate", err)
		f.Seek(ctx, 0, io.SeekStart)
		_, err = f.Write(ctx, []byte("aa"))
		checkError2("fwrite", err)
		_, err = f.WriteAt(ctx, []byte("aa"), 0)
		checkError2("fwriteat", err)
		f.Seek(ctx, 0, io.SeekStart)
		_, err = f.Write(ctx, []byte("aa"))
		checkError2("fwritestring", err)
		f.Seek(ctx, 0, io.SeekStart)
		_, err = f.WriteTo(ctx, bytes.NewBufferString("aaa"))
		checkError2("fwriteto", err)
	})
}

func TestGlob(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		for _, dir := range []string{"", "dir1", "dir2", "dir3"} {
			if dir != "" {
				err := fs.Mkdir(context.Background(), join(testDir, dir), 0o755)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, file := range []string{"abc.ext", "ab1.ext", "ab9.ext", "test", "tes"} {
				err := fs.WriteFile(context.Background(), join(testDir, dir, file), []byte("hello world!"), 0o666)
				if err != nil {
					t.Fatal(err)
				}
			}
		}

		matches1, err := fs.WithContext(context.Background()).Glob(path.Join(testDir, "ab[0-9].ext"))
		if err != nil {
			t.Fatal(err)
		}
		expected1 := []string{path.Join(testDir, "ab1.ext"), path.Join(testDir, "ab9.ext")}

		if !reflect.DeepEqual(matches1, expected1) {
			t.Errorf("unexpected matches: %v != %v", matches1, expected1)
		}

		matches2, err := fs.WithContext(context.Background()).Glob(path.Join(testDir, "tes?"))
		if err != nil {
			t.Fatal(err)
		}
		expected2 := []string{path.Join(testDir, "test")}

		if !reflect.DeepEqual(matches2, expected2) {
			t.Errorf("unexpected matches: %v != %v", matches2, expected2)
		}

		matches3, err := fs.WithContext(context.Background()).Glob(path.Join(testDir, "dir[0-2]/ab[0-9].ext"))
		if err != nil {
			t.Fatal(err)
		}
		expected3 := []string{path.Join(testDir, "dir1", "ab1.ext"), path.Join(testDir, "dir1", "ab9.ext"), path.Join(testDir, "dir2", "ab1.ext"), path.Join(testDir, "dir2", "ab9.ext")}

		if !reflect.DeepEqual(matches3, expected3) {
			t.Errorf("unexpected matches: %v != %v", matches3, expected3)
		}

		matches4, err := fs.WithContext(context.Background()).Glob(path.Join(testDir, "*/ab[0-9].ext"))
		if err != nil {
			t.Fatal(err)
		}
		expected4 := []string{path.Join(testDir, "dir1", "ab1.ext"), path.Join(testDir, "dir1", "ab9.ext"), path.Join(testDir, "dir2", "ab1.ext"), path.Join(testDir, "dir2", "ab9.ext"), path.Join(testDir, "dir3", "ab1.ext"), path.Join(testDir, "dir3", "ab9.ext")}

		if !reflect.DeepEqual(matches4, expected4) {
			t.Errorf("unexpected matches: %v != %v", matches4, expected4)
		}

		matches5, err := fs.WithContext(context.Background()).Glob(path.Join(testDir, "*/abcd"))
		if err != nil {
			t.Fatal(err)
		}
		var expected5 []string

		if !reflect.DeepEqual(matches5, expected5) {
			t.Errorf("unexpected matches: %v != %v", matches5, expected5)
		}
	})
}

func TestFileEdgeCases(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		// 1. Zero-byte file operations
		emptyPath := join(testDir, "empty.txt")
		ef, err := fs.Create(context.Background(), emptyPath)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 10)
		n, err := ef.Read(context.Background(), buf)
		if n != 0 || err != io.EOF {
			t.Errorf("expected 0 bytes and io.EOF reading empty file, got n=%d, err=%v", n, err)
		}
		require.NoError(t, ef.Close(context.Background()))

		// 2. ReadAt and WriteAt offset testing
		atPath := join(testDir, "readwriteat.txt")
		af, err := fs.OpenFile(context.Background(), atPath, os.O_RDWR|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatal(err)
		}
		defer af.Close(context.Background())

		initialData := []byte("0123456789ABCDEF")
		_, err = af.Write(context.Background(), initialData)
		if err != nil {
			t.Fatal(err)
		}

		_, err = af.WriteAt(context.Background(), []byte("XXXX"), 4)
		if err != nil {
			t.Fatal(err)
		}

		readBuf := make([]byte, 4)
		n, err = af.ReadAt(context.Background(), readBuf, 4)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if string(readBuf[:n]) != "XXXX" {
			t.Errorf("ReadAt expected 'XXXX', got %q", string(readBuf[:n]))
		}

		// 3. OpenFile modes: O_TRUNC, O_CREATE|O_EXCL, O_RDONLY
		truncPath := join(testDir, "trunc.txt")
		err = fs.WriteFile(context.Background(), truncPath, []byte("hello world"), 0o666)
		if err != nil {
			t.Fatal(err)
		}

		tf, err := fs.OpenFile(context.Background(), truncPath, os.O_RDWR|os.O_TRUNC, 0o666)
		if err != nil {
			t.Fatal(err)
		}
		stat, err := tf.Stat(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if stat.Size() != 0 {
			t.Errorf("expected size 0 after O_TRUNC, got %d", stat.Size())
		}
		tf.Close(context.Background())

		// O_CREATE | O_EXCL on existing file should fail with ErrExist
		_, err = fs.OpenFile(context.Background(), truncPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
		if !errors.Is(err, os.ErrExist) {
			t.Errorf("expected ErrExist when creating existing file with O_EXCL, got %v", err)
		}

		// O_RDONLY write attempt should fail
		roFile, err := fs.OpenFile(context.Background(), truncPath, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = roFile.Write(context.Background(), []byte("fail"))
		if err == nil {
			t.Error("expected error writing to O_RDONLY file, got nil")
		}
		roFile.Close(context.Background())

		// 4. Large buffer Read/Write
		largePath := join(testDir, "large.bin")
		largeData := make([]byte, 3*1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 251)
		}
		err = fs.WriteFile(context.Background(), largePath, largeData, 0o666)
		if err != nil {
			t.Fatal(err)
		}
		readLarge, err := fs.ReadFile(context.Background(), largePath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(largeData, readLarge) {
			t.Error("large file read content mismatch")
		}
	})
}

func TestDirectoryEdgeCases(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		// 1. MkdirAll deeply nested
		deepPath := join(testDir, "sub1", "sub2", "sub3", "sub4")
		err := fs.MkdirAll(context.Background(), deepPath, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		filePath := join(deepPath, "nested.txt")
		err = fs.WriteFile(context.Background(), filePath, []byte("nested content"), 0o666)
		if err != nil {
			t.Fatal(err)
		}

		st, err := fs.Stat(context.Background(), filePath)
		if err != nil {
			t.Fatal(err)
		}
		if st.Name() != "nested.txt" {
			t.Errorf("expected stat name 'nested.txt', got %q", st.Name())
		}

		// 2. Remove non-empty directory (should return error)
		nonEmptyDir := join(testDir, "sub1")
		err = fs.Remove(context.Background(), nonEmptyDir)
		if err == nil {
			t.Error("expected error when calling Remove on non-empty directory, got nil")
		}

		// 3. RemoveAll deep tree
		err = fs.RemoveAll(context.Background(), nonEmptyDir)
		if err != nil {
			t.Fatalf("RemoveAll failed: %v", err)
		}

		// 4. Unicode & Special Character Filenames
		unicodeDir := join(testDir, "日本語フォルダ")
		err = fs.Mkdir(context.Background(), unicodeDir, 0o755)
		if err != nil {
			t.Fatalf("Mkdir with unicode failed: %v", err)
		}
		unicodeFile := join(unicodeDir, "テスト ファイル #1.txt")
		err = fs.WriteFile(context.Background(), unicodeFile, []byte("ユニコードテスト"), 0o666)
		if err != nil {
			t.Fatalf("WriteFile with unicode failed: %v", err)
		}

		readBack, err := fs.ReadFile(context.Background(), unicodeFile)
		if err != nil {
			t.Fatalf("ReadFile with unicode failed: %v", err)
		}
		if string(readBack) != "ユニコードテスト" {
			t.Errorf("unicode file content mismatch: got %q", string(readBack))
		}

		// 5. Slash and Backslash mixing
		mixedPath := testDir + "/slashSub/backslashSub\\file.txt"
		err = fs.MkdirAll(context.Background(), testDir+"/slashSub/backslashSub", 0o755)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.WriteFile(context.Background(), mixedPath, []byte("mixed path"), 0o666)
		if err != nil {
			t.Fatal(err)
		}
		stMixed, err := fs.Stat(context.Background(), mixedPath)
		if err != nil {
			t.Fatal(err)
		}
		if stMixed.Size() != int64(len("mixed path")) {
			t.Errorf("unexpected size for mixed path file: %d", stMixed.Size())
		}

		// 6. Invalid operation types: Readdir on regular file
		f, err := fs.Open(context.Background(), unicodeFile)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close(context.Background())
		_, err = f.Readdir(context.Background(), -1)
		if err == nil {
			t.Error("expected error calling Readdir on a regular file, got nil")
		}
	})
}

func TestRenameEdgeCases(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		// 1. Move file into subfolder
		subDir := join(testDir, "subdir")
		err := fs.Mkdir(context.Background(), subDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}

		srcFile := join(testDir, "src.txt")
		dstFile := join(subDir, "dst.txt")
		err = fs.WriteFile(context.Background(), srcFile, []byte("move test"), 0o666)
		if err != nil {
			t.Fatal(err)
		}

		err = fs.Rename(context.Background(), srcFile, dstFile)
		if err != nil {
			t.Fatalf("Rename across subfolders failed: %v", err)
		}

		content, err := fs.ReadFile(context.Background(), dstFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "move test" {
			t.Errorf("unexpected content after rename: %q", string(content))
		}

		// 2. Rename directory
		oldDir := join(testDir, "oldDir")
		newDir := join(testDir, "newDir")
		err = fs.Mkdir(context.Background(), oldDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.WriteFile(context.Background(), join(oldDir, "inside.txt"), []byte("inside"), 0o666)
		if err != nil {
			t.Fatal(err)
		}

		err = fs.Rename(context.Background(), oldDir, newDir)
		if err != nil {
			t.Fatalf("Rename directory failed: %v", err)
		}

		insideContent, err := fs.ReadFile(context.Background(), join(newDir, "inside.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(insideContent) != "inside" {
			t.Errorf("unexpected content inside renamed directory: %q", string(insideContent))
		}
	})
}

func TestLargeFileCopy(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		srcPath := join(testDir, "large_100mb_src.bin")
		dstPath := join(testDir, "large_100mb_dst.bin")

		// 100MB (100 * 1024 * 1024 = 104,857,600 bytes)
		const totalSize = 100 * 1024 * 1024
		const chunkSize = 1 * 1024 * 1024 // 1MB

		sf, err := fs.Create(context.Background(), srcPath)
		if err != nil {
			t.Fatal(err)
		}

		srcHasher := sha256.New()
		chunk := make([]byte, chunkSize)

		written := 0
		for written < totalSize {
			toWrite := min(totalSize-written, chunkSize)
			for i := range toWrite {
				pos := written + i
				chunk[i] = byte((pos*31 + 7) % 251)
			}
			n, err := sf.Write(context.Background(), chunk[:toWrite])
			if err != nil {
				sf.Close(context.Background())
				t.Fatalf("Write failed at %d bytes: %v", written, err)
			}
			srcHasher.Write(chunk[:n])
			written += n
		}
		sf.Close(context.Background())

		// Copy via io.Copy (tests ReadFrom / ServerSideCopy or streaming Read/Write)
		sf, err = fs.Open(context.Background(), srcPath)
		if err != nil {
			t.Fatal(err)
		}
		defer sf.Close(context.Background())

		df, err := fs.Create(context.Background(), dstPath)
		if err != nil {
			t.Fatal(err)
		}

		copied, err := io.Copy(df.WithContext(context.Background()), sf.WithContext(context.Background()))
		if err != nil {
			df.Close(context.Background())
			t.Fatalf("io.Copy failed: %v", err)
		}
		df.Close(context.Background())

		if copied != int64(totalSize) {
			t.Errorf("copied size mismatch: expected %d, got %d", totalSize, copied)
		}

		// Verify copied file size and checksum
		dstFile, err := fs.Open(context.Background(), dstPath)
		if err != nil {
			t.Fatal(err)
		}
		defer dstFile.Close(context.Background())

		stat, err := dstFile.Stat(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if stat.Size() != int64(totalSize) {
			t.Errorf("dst stat size mismatch: expected %d, got %d", totalSize, stat.Size())
		}

		dstHasher := sha256.New()
		readBuf := make([]byte, chunkSize)
		for {
			n, err := dstFile.Read(context.Background(), readBuf)
			if n > 0 {
				dstHasher.Write(readBuf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("dstRead failed: %v", err)
			}
		}

		if !bytes.Equal(srcHasher.Sum(nil), dstHasher.Sum(nil)) {
			t.Error("SHA256 checksum mismatch between src and copied dst file")
		}
	})
}

func TestWaitForChange(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		type outcome struct {
			res notify.Result
			err error
		}

		t.Run("NonRecursive", func(t *testing.T) {
			d, err := fs.Open(context.Background(), testDir)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close(context.Background())

			ch := make(chan outcome, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			go func() {
				res, err := d.WaitForChange(ctx, notify.FileName, false)
				ch <- outcome{res: res, err: err}
			}()

			// Allow request to reach the server.
			time.Sleep(100 * time.Millisecond)

			filePath := join(testDir, "created.txt")
			f, err := fs.Create(context.Background(), filePath)
			if err != nil {
				t.Fatal(err)
			}
			_ = f.Close(context.Background())

			select {
			case out := <-ch:
				if out.err != nil {
					t.Fatalf("WaitForChange failed: %v", out.err)
				}
				if out.res.RescanRequired {
					// Server (e.g. macOS smbd) signaled directory change via STATUS_NOTIFY_ENUM_DIR.
					return
				}
				found := false
				for _, e := range out.res.Events {
					if e.Name == "created.txt" {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected created.txt in events, got: %+v", out.res.Events)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for WaitForChange")
			}
		})

		t.Run("WatchTree", func(t *testing.T) {
			d, err := fs.Open(context.Background(), testDir)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close(context.Background())

			ch := make(chan outcome, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			go func() {
				res, err := d.WaitForChange(ctx, notify.FileName, true)
				ch <- outcome{res: res, err: err}
			}()

			// Allow request to reach the server.
			time.Sleep(100 * time.Millisecond)

			filePath := join(testDir, "watchtree_created.txt")
			f, err := fs.Create(context.Background(), filePath)
			if err != nil {
				t.Fatal(err)
			}
			_ = f.Close(context.Background())

			select {
			case out := <-ch:
				if out.err != nil {
					t.Fatalf("WaitForChange failed: %v", out.err)
				}
				if out.res.RescanRequired {
					// Server signaled directory change via STATUS_NOTIFY_ENUM_DIR.
					return
				}
				found := false
				for _, e := range out.res.Events {
					if e.Name == "watchtree_created.txt" {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected watchtree_created.txt in events, got: %+v", out.res.Events)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for WaitForChange")
			}
		})

		t.Run("ContextCancellation", func(t *testing.T) {
			d, err := fs.Open(context.Background(), testDir)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close(context.Background())

			ctx, cancel := context.WithCancel(context.Background())
			ch := make(chan outcome, 1)

			go func() {
				res, err := d.WaitForChange(ctx, notify.FileName, false)
				ch <- outcome{res: res, err: err}
			}()

			// Allow request to reach the server.
			time.Sleep(100 * time.Millisecond)

			cancel()

			select {
			case out := <-ch:
				if !errors.Is(out.err, context.Canceled) {
					t.Fatalf("expected context.Canceled, got: %v", out.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for canceled WaitForChange")
			}

			// Ensure connection and share remain usable after request cancellation.
			if _, err := fs.Stat(context.Background(), testDir); err != nil {
				t.Fatalf("share unusable after WaitForChange cancellation: %v", err)
			}
		})

		t.Run("InvalidTarget", func(t *testing.T) {
			regularPath := join(testDir, "regular.txt")
			f, err := fs.Create(context.Background(), regularPath)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close(context.Background())

			_, err = f.WaitForChange(context.Background(), notify.FileName, false)
			if !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("expected os.ErrInvalid on regular file, got: %v", err)
			}
		})
	})
}

func TestFileLock(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		filePath := join(testDir, "locked.txt")
		f1, err := fs.OpenFile(context.Background(), filePath, os.O_RDWR|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatal(err)
		}
		defer f1.Close(context.Background())

		data := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
		if _, err := f1.Write(context.Background(), data); err != nil {
			t.Fatal(err)
		}

		t.Run("ExclusiveLockAndUnlock", func(t *testing.T) {
			err := f1.Lock(context.Background(), []smb2.LockRange{
				{Range: smb2.ByteRange{Offset: 0, Length: 10}, Exclusive: true},
			}, true)
			if err != nil {
				t.Fatalf("failed to acquire exclusive lock: %v", err)
			}

			err = f1.Unlock(context.Background(), []smb2.ByteRange{
				{Offset: 0, Length: 10},
			})
			if err != nil {
				t.Fatalf("failed to unlock: %v", err)
			}
		})

		t.Run("LockConflict", func(t *testing.T) {
			f2, err := fs.OpenFile(context.Background(), filePath, os.O_RDWR, 0o666)
			if err != nil {
				t.Fatal(err)
			}
			defer f2.Close(context.Background())

			err = f1.Lock(context.Background(), []smb2.LockRange{
				{Range: smb2.ByteRange{Offset: 10, Length: 10}, Exclusive: true},
			}, true)
			if err != nil {
				t.Fatalf("f1 failed to acquire exclusive lock: %v", err)
			}
			defer func() {
				_ = f1.Unlock(context.Background(), []smb2.ByteRange{{Offset: 10, Length: 10}})
			}()

			err = f2.Lock(context.Background(), []smb2.LockRange{
				{Range: smb2.ByteRange{Offset: 15, Length: 10}, Exclusive: true},
			}, true)
			if err == nil {
				t.Fatal("expected error on conflicting lock, got nil")
			}
			if _, ok := errors.AsType[*protocol.ResponseError](err); !ok {
				t.Fatalf("expected ResponseError on lock conflict, got: %v", err)
			}

			err = f1.Unlock(context.Background(), []smb2.ByteRange{{Offset: 10, Length: 10}})
			if err != nil {
				t.Fatalf("f1 failed to unlock: %v", err)
			}

			err = f2.Lock(context.Background(), []smb2.LockRange{
				{Range: smb2.ByteRange{Offset: 15, Length: 10}, Exclusive: true},
			}, true)
			if err != nil {
				t.Fatalf("f2 failed to acquire lock after f1 unlocked: %v", err)
			}
			_ = f2.Unlock(context.Background(), []smb2.ByteRange{{Offset: 15, Length: 10}})
		})

		t.Run("SharedLocks", func(t *testing.T) {
			f2, err := fs.OpenFile(context.Background(), filePath, os.O_RDWR, 0o666)
			if err != nil {
				t.Fatal(err)
			}
			defer f2.Close(context.Background())

			err = f1.Lock(context.Background(), []smb2.LockRange{
				{Range: smb2.ByteRange{Offset: 20, Length: 10}, Exclusive: false},
			}, true)
			if err != nil {
				t.Fatalf("f1 failed to acquire shared lock: %v", err)
			}
			defer func() {
				_ = f1.Unlock(context.Background(), []smb2.ByteRange{{Offset: 20, Length: 10}})
			}()

			err = f2.Lock(context.Background(), []smb2.LockRange{
				{Range: smb2.ByteRange{Offset: 20, Length: 10}, Exclusive: false},
			}, true)
			if err != nil {
				t.Fatalf("f2 failed to acquire shared lock on same range: %v", err)
			}
			defer func() {
				_ = f2.Unlock(context.Background(), []smb2.ByteRange{{Offset: 20, Length: 10}})
			}()

			err = f2.Lock(context.Background(), []smb2.LockRange{
				{Range: smb2.ByteRange{Offset: 20, Length: 10}, Exclusive: true},
			}, true)
			if err == nil {
				t.Fatal("expected error on exclusive lock over shared lock, got nil")
			}
		})

		t.Run("MultiRange", func(t *testing.T) {
			ranges := []smb2.LockRange{
				{Range: smb2.ByteRange{Offset: 0, Length: 5}, Exclusive: true},
				{Range: smb2.ByteRange{Offset: 10, Length: 5}, Exclusive: true},
			}
			err := f1.Lock(context.Background(), ranges, true)
			if err != nil {
				t.Fatalf("failed to acquire multi-range lock: %v", err)
			}

			unlockRanges := []smb2.ByteRange{
				{Offset: 0, Length: 5},
				{Offset: 10, Length: 5},
			}
			err = f1.Unlock(context.Background(), unlockRanges)
			if err != nil {
				t.Fatalf("failed to unlock multi-range: %v", err)
			}
		})
	})
}

func TestSecurityDescriptor(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		filePath := join(testDir, "sec.txt")
		f, err := fs.Create(context.Background(), filePath)
		if err != nil {
			t.Fatal(err)
		}
		f.Close(context.Background())

		checkSupported := func(t *testing.T, err error) {
			t.Helper()
			var rerr *protocol.ResponseError
			if errors.As(err, &rerr) && rerr.Code == 0xC00000BB /* STATUS_NOT_SUPPORTED */ {
				t.Skip("server does not support security descriptors (STATUS_NOT_SUPPORTED)")
			}
		}

		t.Run("QueryOwnerAndGroup", func(t *testing.T) {
			sd, err := fs.GetSecurityDescriptor(context.Background(), filePath, security.Owner|security.Group)
			if err != nil {
				checkSupported(t, err)
				t.Fatalf("failed to query owner/group security descriptor: %v", err)
			}
			if sd.Owner == nil {
				t.Fatal("expected owner to be non-nil")
			}
			if sd.Group == nil {
				t.Fatal("expected group to be non-nil")
			}
		})

		t.Run("QueryDACL", func(t *testing.T) {
			sd, err := fs.GetSecurityDescriptor(context.Background(), filePath, security.DACL)
			if err != nil {
				checkSupported(t, err)
				t.Fatalf("failed to query DACL security descriptor: %v", err)
			}
			if sd == nil {
				t.Fatal("expected security descriptor to be non-nil")
			}
		})

		t.Run("SetDACL", func(t *testing.T) {
			sd, err := fs.GetSecurityDescriptor(context.Background(), filePath, security.DACL)
			if err != nil {
				checkSupported(t, err)
				t.Fatalf("failed to query DACL before set: %v", err)
			}
			err = fs.SetSecurityDescriptor(context.Background(), filePath, sd)
			if err != nil {
				checkSupported(t, err)
				var rerr *protocol.ResponseError
				if errors.As(err, &rerr) && rerr.Code == 0xC0000022 /* STATUS_ACCESS_DENIED */ {
					t.Skip("account is not permitted to set the DACL")
				}
				t.Fatalf("failed to set DACL: %v", err)
			}
		})
	})
}

type dfsIntegrationConfig struct {
	server, target, secondTarget string
	share, link                  string
	addresses                    map[string]string
	credentials                  auth.NTLMCredential
}

func loadDFSIntegrationConfig(t *testing.T) dfsIntegrationConfig {
	t.Helper()
	if dfsEnv == nil {
		t.Skip("DFS entry is not configured in client_conf.json")
	}
	e := dfsEnv
	require.Equal(t, "tcp", e.Transport.Type, "DFS transport type")
	require.Equal(t, "ntlm", e.Session.Type, "DFS session type")
	server, target, secondTarget := e.Transport.Host, e.DFS.Target, e.DFS.SecondTarget
	require.NotEmpty(t, server, "transport.host")
	require.NotEmpty(t, target, "dfs.target")
	require.NotEmpty(t, secondTarget, "dfs.second_target")
	require.NotEqual(t, server, target)
	require.NotEqual(t, server, secondTarget)
	require.NotEqual(t, target, secondTarget)
	addr := net.JoinHostPort(e.Transport.Host, strconv.Itoa(e.Transport.Port))
	cfg := dfsIntegrationConfig{
		server: server, target: target, secondTarget: secondTarget,
		share: e.TreeConn.Share1, link: e.DFS.Link,
		addresses: map[string]string{
			server:       addr,
			target:       addr,
			secondTarget: addr,
		},
		credentials: auth.NTLMCredential{
			User: e.Session.User, Password: e.Session.Password,
			Domain: e.Session.Domain, Workstation: e.Session.Workstation,
			TargetSPN: e.Session.TargetSPN,
		},
	}
	require.NotEmpty(t, cfg.share, "tree_conn.share1")
	require.NotEmpty(t, cfg.link, "dfs.link")
	require.NotEmpty(t, cfg.credentials.User, "session.user")
	require.NotEmpty(t, cfg.credentials.Password, "session.passwd")
	return cfg
}

type dfsIntegrationClient struct {
	client      *smbclient.Client
	dialer      *smb2.Dialer
	ctx         context.Context
	mu          sync.Mutex
	connections map[string]int
	sessions    map[string]*smb2.Session
}

func newDFSIntegrationClient(t *testing.T, cfg dfsIntegrationConfig) *dfsIntegrationClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	c := &dfsIntegrationClient{ctx: ctx, connections: make(map[string]int), sessions: make(map[string]*smb2.Session)}
	dialer := &smb2.Dialer{
		Credentials: cfg.credentials,
		TransportDialer: transportDialerFunc(func(ctx context.Context, server string) (smb2.Transport, error) {
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
			return smb2.NewTransport(conn), nil
		}),
		RequireMessageSigning: true,
	}
	c.dialer = dialer
	c.client = smbclient.New(dialer)
	t.Cleanup(func() {
		require.NoError(t, c.client.Close())
		c.mu.Lock()
		sessions := make([]*smb2.Session, 0, len(c.sessions))
		for _, s := range c.sessions {
			sessions = append(sessions, s)
		}
		c.mu.Unlock()
		for _, s := range sessions {
			require.NoError(t, s.Close())
		}
	})
	return c
}

func (c *dfsIntegrationClient) mount(t *testing.T, server, share string) *smb2.Share {
	t.Helper()
	c.mu.Lock()
	session := c.sessions[strings.ToLower(server)]
	c.mu.Unlock()
	if session == nil {
		var err error
		session, err = c.dialer.Dial(c.ctx, server)
		require.NoError(t, err)
		c.mu.Lock()
		if existing := c.sessions[strings.ToLower(server)]; existing != nil {
			session.Close()
			session = existing
		} else {
			c.sessions[strings.ToLower(server)] = session
		}
		c.mu.Unlock()
	}
	fs, err := session.Mount(c.ctx, share)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, fs.Unmount(context.Background())) })
	return fs
}

func (c *dfsIntegrationClient) removeOnCleanup(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() {
		err := c.client.Remove(context.Background(), path)
		if !errors.Is(err, os.ErrNotExist) {
			require.NoError(t, err)
		}
	})
}

func (c *dfsIntegrationClient) connectionCounts() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	counts := make(map[string]int, len(c.connections))
	maps.Copy(counts, c.connections)
	return counts
}

// The fixture has link and link-alias pointing at target/dfs-target, and
// link-extra pointing at secondTarget/dfs-encrypted/nested. The latter share
// requires SMB encryption. All three logical servers may use one Samba daemon.
func TestDFSIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	cfg := loadDFSIntegrationConfig(t)
	namespace := `\\` + join(cfg.server, cfg.share)

	t.Run("context_filesystem", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		root := join(cfg.link, "context-fs-"+rand.Text())
		testClientContextFS(t, c.client, c.ctx, cfg.server, cfg.share, root)
	})

	t.Run("referral_and_cache", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		c.mu.Lock()
		s := c.sessions[strings.ToLower(cfg.server)]
		c.mu.Unlock()
		if s == nil {
			var e error
			s, e = c.dialer.Dial(c.ctx, cfg.server)
			require.NoError(t, e)
			c.mu.Lock()
			c.sessions[strings.ToLower(cfg.server)] = s
			c.mu.Unlock()
		}
		shares, err := s.ListShareNames(c.ctx)
		require.NoError(t, err)
		require.Contains(t, shares, cfg.share)
		name := join(namespace, cfg.link, fmt.Sprintf("go-smb2-dfs-%d.txt", time.Now().UnixNano()))
		t.Cleanup(func() { require.NoError(t, c.client.Remove(context.Background(), name)) })
		payload := []byte("DFS referral integration test\n")
		require.NoError(t, c.client.WriteFile(c.ctx, name, payload, 0o600))
		before := c.connectionCounts()
		got, err := c.client.ReadFile(c.ctx, name)
		require.NoError(t, err)
		require.Equal(t, payload, got)
		require.Equal(t, 1, before[cfg.target])
		require.Equal(t, before, c.connectionCounts(), "cached target should reuse its transport")
	})

	t.Run("prefixes_aliases_and_rename", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		directory := fmt.Sprintf("go-smb2-dfs-%d-日本語", time.Now().UnixNano())
		plainPath := join(namespace, cfg.link, directory, "同名.txt")
		encryptedPath := join(namespace, cfg.link+"-extra", directory, "同名.txt")
		plain := bytes.Repeat([]byte("plain"), 300000)
		encrypted := bytes.Repeat([]byte("encrypted"), 200000)
		for _, link := range []string{cfg.link, cfg.link + "-extra"} {
			path := join(namespace, link, directory)
			require.NoError(t, c.client.Mkdir(c.ctx, path, 0o700))
			t.Cleanup(func() { require.NoError(t, c.client.Remove(context.Background(), path)) })
		}
		c.removeOnCleanup(t, plainPath)
		c.removeOnCleanup(t, encryptedPath)
		require.NoError(t, c.client.WriteFile(c.ctx, plainPath, plain, 0o600))
		require.NoError(t, c.client.WriteFile(c.ctx, encryptedPath, encrypted, 0o600))

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

		aliasPath := join(namespace, cfg.link+"-alias", directory, "変更.txt")
		c.removeOnCleanup(t, aliasPath)
		require.NoError(t, c.client.Rename(c.ctx, plainPath, aliasPath))
		got, err = c.client.ReadFile(c.ctx, join(namespace, cfg.link, directory, "変更.txt"))
		require.NoError(t, err)
		require.Equal(t, plain, got)
		_, err = c.client.Stat(c.ctx, plainPath)
		require.ErrorIs(t, err, os.ErrNotExist)

		crossTarget := join(namespace, cfg.link+"-extra", directory, "移動.txt")
		require.ErrorContains(t, c.client.Rename(c.ctx, aliasPath, crossTarget), "cross-share")
		got, err = c.client.ReadFile(c.ctx, aliasPath)
		require.NoError(t, err)
		require.Equal(t, plain, got, "rejected cross-target rename must preserve the source")
		_, err = c.client.Stat(c.ctx, crossTarget)
		require.ErrorIs(t, err, os.ErrNotExist)
		got, err = c.client.ReadFile(c.ctx, encryptedPath)
		require.NoError(t, err)
		require.Equal(t, encrypted, got)
		require.Equal(t, map[string]int{cfg.server: 1, cfg.target: 2, cfg.secondTarget: 2}, c.connectionCounts())
	})

	t.Run("concurrent_cold_referrals", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		const workers = 8
		start := make(chan struct{})
		results := make(chan error, workers)
		prefix := fmt.Sprintf("go-smb2-dfs-%d", time.Now().UnixNano())
		for i := range workers {
			link := cfg.link
			if i%2 != 0 {
				link += "-extra"
			}
			path := join(namespace, link, fmt.Sprintf("%s-%d-並行.txt", prefix, i))
			t.Cleanup(func() { require.NoError(t, c.client.Remove(context.Background(), path)) })
			go func() {
				<-start
				payload := bytes.Repeat([]byte(fmt.Sprintf("worker-%d", i)), 16000)
				if err := c.client.WriteFile(c.ctx, path, payload, 0o600); err != nil {
					results <- fmt.Errorf("write %s: %w", path, err)
					return
				}
				got, err := c.client.ReadFile(c.ctx, path)
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

	t.Run("close_invalidates_open_file", func(t *testing.T) {
		c := newDFSIntegrationClient(t, cfg)
		name := fmt.Sprintf("go-smb2-dfs-%d.txt", time.Now().UnixNano())
		path := join(namespace, cfg.link, name)
		cleanup := smbclient.New(c.dialer)
		t.Cleanup(func() {
			err := cleanup.Remove(context.Background(), path)
			if !errors.Is(err, os.ErrNotExist) {
				require.NoError(t, err)
			}
			require.NoError(t, cleanup.Close())
		})
		payload := []byte("file bound to a DFS client session")
		require.NoError(t, c.client.WriteFile(c.ctx, path, payload, 0o600))
		alias := join(namespace, cfg.link+"-alias", name)
		file, err := c.client.Open(c.ctx, alias)
		require.NoError(t, err)
		require.Equal(t, alias, file.Name())
		got := make([]byte, len(payload))
		n, err := file.ReadAt(c.ctx, got, 0)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
		require.Equal(t, payload, got)
		require.NoError(t, c.client.Close())
		_, err = file.ReadAt(context.Background(), got, 0)
		require.Error(t, err, "Close must invalidate existing Files")
		_ = file.Close(context.Background())
		_, err = c.client.Open(context.Background(), path)
		require.Error(t, err, "Close must reject new operations")
	})
}

// testClientContextFS exercises both direct shares and DFS namespace paths.
func testClientContextFS(t *testing.T, c *smbclient.Client, ctx context.Context, server, share, root string) {
	t.Helper()
	network := c.WithContext(ctx)
	entries, err := network.ReadDir(".")
	require.NoError(t, err)
	require.Empty(t, entries, "a new client must not discover servers implicitly")

	// Access the server directly before it appears in the cache listing.
	entries, err = network.ReadDir(server)
	skipPermissionDenied(t, err)
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(entries, func(entry iofs.DirEntry) bool {
		return strings.EqualFold(entry.Name(), share) && entry.IsDir()
	}), "configured share must be listed")
	entries, err = network.ReadDir(".")
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(entries, func(entry iofs.DirEntry) bool {
		return strings.EqualFold(entry.Name(), server) && entry.IsDir()
	}), "direct access must populate the virtual root")

	unc := `\\` + join(server, share, root)
	require.NoError(t, c.MkdirAll(ctx, join(unc, "nested"), 0o700))
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		require.NoError(t, c.RemoveAll(cleanupCtx, unc))
	})
	payload := []byte("client io/fs integration\n")
	for _, name := range []string{"hello.txt", `nested\world.txt`} {
		require.NoError(t, c.WriteFile(ctx, join(unc, name), payload, 0o600))
	}
	// On Windows NTFS, writing inside a child directory modifies its MFT record
	// but can lag in flushing to the parent directory index. Synchronize the
	// directory timestamp so ReadDir and Stat match for fstest.TestFS.
	nestedPath := join(unc, "nested")
	nestedInfo, err := c.Stat(ctx, nestedPath)
	require.NoError(t, err)
	require.NoError(t, c.Chtimes(ctx, nestedPath, nestedInfo.ModTime(), nestedInfo.ModTime()))
	virtualRoot := strings.ReplaceAll(join(server, share, root), `\`, "/")
	project, err := iofs.Sub(network, virtualRoot)
	require.NoError(t, err)
	require.NoError(t, fstest.TestFS(project, "hello.txt", "nested", "nested/world.txt"))

	data, err := iofs.ReadFile(project, "nested/world.txt")
	require.NoError(t, err)
	require.Equal(t, payload, data)
	f, err := project.Open("hello.txt")
	require.NoError(t, err)
	data, readErr := io.ReadAll(f)
	closeErr := f.Close()
	require.NoError(t, readErr)
	require.NoError(t, closeErr)
	require.Equal(t, payload, data)

	var visited []string
	require.NoError(t, iofs.WalkDir(project, ".", func(name string, _ iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		visited = append(visited, name)
		return nil
	}))
	require.Equal(t, []string{".", "hello.txt", "nested", "nested/world.txt"}, visited)
	for pattern, want := range map[string][]string{
		"*.txt":            {"hello.txt"},
		"*/*.txt":          {"nested/world.txt"},
		"nested/[vw]*.txt": {"nested/world.txt"},
	} {
		matches, err := iofs.Glob(project, pattern)
		require.NoError(t, err)
		require.Equal(t, want, matches)
	}
	matches, err := network.Glob(virtualRoot + "/*/*.txt")
	require.NoError(t, err)
	require.Equal(t, []string{virtualRoot + "/nested/world.txt"}, matches)

	_, err = project.Open("../escape")
	require.ErrorIs(t, err, iofs.ErrInvalid)
	_, err = iofs.Stat(project, "missing")
	require.ErrorIs(t, err, iofs.ErrNotExist)
	var pathErr *iofs.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, "missing", pathErr.Path)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = c.WithContext(canceled).ReadDir(".")
	require.ErrorIs(t, err, context.Canceled)
	// Closing an adapter file and canceling another adapter must leave the
	// owning client and the original adapter usable.
	_, err = iofs.Stat(project, "hello.txt")
	require.NoError(t, err)
}

func TestContextClient(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		// fstest.TestFS performs many sequential requests on remote servers.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		c := smbclient.New(e.dialer)
		t.Cleanup(func() { require.NoError(t, c.Close()) })
		root := "context-fs-" + rand.Text()
		testClientContextFS(t, c, ctx, e.cfg.Transport.Host, e.cfg.TreeConn.Share1, root)
	})
}

func contextSubFS(share *smb2.Share, root string) iofs.FS {
	bound := share.WithContext(context.Background())
	fs, err := iofs.Sub(bound, strings.ReplaceAll(root, `\`, "/"))
	if err != nil {
		panic(err)
	}
	return fs
}

func TestContextShare(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		err := fs.WriteFile(context.Background(), path.Join(testDir, "hello.txt"), []byte("hello world!"), 0o666)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.Mkdir(context.Background(), path.Join(testDir, "hello"), 0o755)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.WriteFile(context.Background(), path.Join(testDir, "hello", "hello2.txt"), []byte("hello world!"), 0o444)
		if err != nil {
			t.Fatal(err)
		}

		{
			var entries []string

			iofs.WalkDir(contextSubFS(fs, testDir), ".", func(path string, d iofs.DirEntry, err error) error {
				if err != nil {
					t.Fatal(err)
				}

				entries = append(entries, path)

				return nil
			})

			if !reflect.DeepEqual(entries, []string{".", "hello", "hello/hello2.txt", "hello.txt"}) {
				t.Error("unexpected result")
			}
		}

		{
			var entries []string

			iofs.WalkDir(contextSubFS(fs, testDir), "hello", func(path string, d iofs.DirEntry, err error) error {
				if err != nil {
					t.Fatal(err)
				}

				entries = append(entries, path)

				return nil
			})

			if !reflect.DeepEqual(entries, []string{"hello", "hello/hello2.txt"}) {
				t.Error("unexpected result")
			}
		}
	})
}

func TestGlobFS(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		err := fs.WriteFile(context.Background(), path.Join(testDir, "hello.txt"), []byte("hello world!"), 0o666)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.Mkdir(context.Background(), path.Join(testDir, "hello"), 0o755)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.WriteFile(context.Background(), path.Join(testDir, "hello", "hello2.txt"), []byte("hello world!"), 0o444)
		if err != nil {
			t.Fatal(err)
		}

		cases := []struct {
			pattern  string
			expected []string
		}{
			{
				pattern:  "hello.txt",
				expected: []string{"hello.txt"},
			},
			{
				pattern:  "hel?o.txt",
				expected: []string{"hello.txt"},
			},
			{
				pattern:  "*",
				expected: []string{"hello", "hello.txt"},
			},
			{
				pattern:  "*/*",
				expected: []string{"hello/hello2.txt"},
			},
		}

		for _, tt := range cases {
			matches, err := iofs.Glob(contextSubFS(fs, testDir), tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(matches, tt.expected) {
				t.Errorf("Glob(%q) = %q, want %q", tt.pattern, matches, tt.expected)
				t.Error("unexpected result")
			}
		}
	})
}

func TestContextShareEdgeCases(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		err := fs.WriteFile(context.Background(), path.Join(testDir, "sample.txt"), []byte("sample content"), 0o666)
		if err != nil {
			t.Fatal(err)
		}

		dirFS := contextSubFS(fs, testDir)

		// 1. Valid path open & read
		f, err := dirFS.Open("sample.txt")
		if err != nil {
			t.Fatalf("dirFS.Open sample.txt failed: %v", err)
		}
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Name() != "sample.txt" {
			t.Errorf("expected sample.txt, got %s", fi.Name())
		}
		f.Close()

		// 2. Invalid path checks (leading slash, parent traversal ..)
		for _, invalidPath := range []string{"/sample.txt", "../sample.txt", "a/../../sample.txt"} {
			_, err := dirFS.Open(invalidPath)
			if err == nil {
				t.Errorf("expected error for invalid io/fs path %q, got nil", invalidPath)
			}
		}

		// 3. ReadFile on ContextShare
		rf, ok := dirFS.(iofs.ReadFileFS)
		if ok {
			content, err := rf.ReadFile("sample.txt")
			if err != nil {
				t.Fatalf("ReadFileFS.ReadFile failed: %v", err)
			}
			if string(content) != "sample content" {
				t.Errorf("unexpected ReadFile content: %q", string(content))
			}
		}

		// 4. StatFS on ContextShare
		sf, ok := dirFS.(iofs.StatFS)
		if ok {
			st, err := sf.Stat("sample.txt")
			if err != nil {
				t.Fatalf("StatFS.Stat failed: %v", err)
			}
			if st.Size() != int64(len("sample content")) {
				t.Errorf("unexpected stat size: %d", st.Size())
			}
		}
	})
}

// TestMultiCreditIO exercises request sizes around the 64 KiB credit boundary so
// that the per-request CreditCharge and MessageId accounting are validated on a
// real server, including dialects that support multi-credit operations.
func TestMultiCreditIO(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		sizes := []int{
			0,
			1,
			64*1024 - 1,
			64 * 1024,
			64*1024 + 1,
			1024 * 1024,
			1024*1024 + 1,
		}

		for _, size := range sizes {
			name := join(testDir, fmt.Sprintf("bulk-%d.bin", size))

			data := make([]byte, size)
			for i := range data {
				data[i] = byte((i*31 + 7) % 251)
			}

			if err := fs.WriteFile(context.Background(), name, data, 0o644); err != nil {
				t.Fatalf("WriteFile(%d bytes): %v", size, err)
			}

			fi, err := fs.Stat(context.Background(), name)
			if err != nil {
				t.Fatalf("Stat(%d bytes): %v", size, err)
			}
			if fi.Size() != int64(size) {
				t.Fatalf("Stat(%d bytes) size = %d", size, fi.Size())
			}

			got, err := fs.ReadFile(context.Background(), name)
			if err != nil {
				t.Fatalf("ReadFile(%d bytes): %v", size, err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("ReadFile(%d bytes) returned %d bytes with different content", size, len(got))
			}

			if err := fs.Remove(context.Background(), name); err != nil {
				t.Fatalf("Remove(%d bytes): %v", size, err)
			}
		}
	})
}

// TestConcurrentShareAccess runs independent read/write cycles in parallel over
// one share so that credit lending, signing/encryption, and response dispatch
// are exercised concurrently rather than one request at a time.
func TestConcurrentShareAccess(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := newTestDirectory(t, fs)

		const (
			workers = 8
			size    = 128 * 1024
		)

		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for w := range workers {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()

				name := join(testDir, fmt.Sprintf("worker-%d.bin", w))
				data := make([]byte, size)
				for i := range data {
					data[i] = byte((i*17 + w*53) % 251)
				}

				if err := fs.WriteFile(context.Background(), name, data, 0o644); err != nil {
					errs <- fmt.Errorf("worker %d: WriteFile: %w", w, err)
					return
				}
				got, err := fs.ReadFile(context.Background(), name)
				if err != nil {
					errs <- fmt.Errorf("worker %d: ReadFile: %w", w, err)
					return
				}
				if !bytes.Equal(got, data) {
					errs <- fmt.Errorf("worker %d: content mismatch", w)
					return
				}
				if err := fs.Remove(context.Background(), name); err != nil {
					errs <- fmt.Errorf("worker %d: Remove: %w", w, err)
				}
			}(w)
		}

		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

// TestKerberosIntegration exercises authentication and required encryption
// across SMB dialects using client_conf.json entries with a kerberos section.
func TestKerberosIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if len(kerberosEnvs) == 0 {
		t.Skip("Kerberos matrix entry is not configured in client_conf.json")
	}
	for _, cfg := range kerberosEnvs {
		t.Run(cfg.Name, func(t *testing.T) {
			require.Equal(t, "tcp", cfg.Transport.Type, "Kerberos matrix transport")
			require.Equal(t, "kerberos", cfg.Session.Type, "Kerberos matrix session")
			require.NotEmpty(t, cfg.TreeConn.Share1, "tree_conn.share1")
			require.NotEmpty(t, cfg.Kerberos.EncryptedShare, "kerberos.encrypted_share")
			creds, err := auth.NewKerberosCredential(auth.KerberosOptions{
				User: cfg.Session.User, Realm: cfg.Session.Realm, Password: cfg.Session.Password,
				ConfigFile: cfg.Session.KRB5Config, TargetSPN: cfg.Session.TargetSPN,
			})
			require.NoError(t, err)
			defer creds.Close()
			host := cfg.Transport.Host
			addr := net.JoinHostPort(host, strconv.Itoa(cfg.Transport.Port))

			for _, dialect := range []uint16{wire.SMB210, wire.SMB302, wire.SMB311} {
				t.Run(fmt.Sprintf("%04x", dialect), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()

					dialer := &smb2.Dialer{
						Credentials:           creds,
						RequireMessageSigning: true,
						SpecifiedDialects:     []smb2.Dialect{smb2.Dialect(dialect)},
						TransportDialer: transportDialerFunc(func(ctx context.Context, _ string) (smb2.Transport, error) {
							tcp, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
							if err != nil {
								return nil, err
							}
							return smb2.NewTransport(tcp), nil
						}),
					}
					session, err := dialer.Dial(ctx, host)
					require.NoError(t, err)
					defer session.Close()

					shares := []string{cfg.TreeConn.Share1}
					if dialect >= wire.SMB300 {
						shares = append(shares, cfg.Kerberos.EncryptedShare)
					}
					for _, name := range shares {
						require.NotEmpty(t, name)
						share, err := session.Mount(ctx, name)
						require.NoError(t, err)
						func() {
							defer share.Unmount(ctx)
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
		})
	}
}

func Example() {
	dialer := &smb2.Dialer{
		Credentials: auth.NTLMCredential{
			User:     "Guest",
			Password: "",
			Domain:   "MicrosoftAccount",
		},
		TransportDialer: smb2.TCPDialer{},
	}
	session, err := dialer.Dial(context.Background(), "localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()

	ctx := context.Background()
	fs, err := session.Mount(ctx, "share")
	if err != nil {
		panic(err)
	}
	defer fs.Unmount(ctx)

	f, err := fs.Create(ctx, "hello.txt")
	if err != nil {
		panic(err)
	}
	defer fs.Remove(ctx, "hello.txt")
	defer f.Close(ctx)

	_, err = f.Write(ctx, []byte("Hello world!"))
	if err != nil {
		panic(err)
	}

	_, err = f.Seek(ctx, 0, io.SeekStart)
	if err != nil {
		panic(err)
	}

	bs, err := io.ReadAll(f.WithContext(ctx))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))

	// Hello world!
}

func TestFileIdentity(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		fs := e.fs
		dir := newTestDirectory(t, fs)
		target := join(dir, "target")
		require.NoError(t, fs.WriteFile(ctx, target, []byte("identity"), 0o600))
		first, err := fs.Stat(ctx, target)
		require.NoError(t, err)
		second, err := fs.Lstat(ctx, target)
		require.NoError(t, err)
		require.True(t, smb2.SameFile(first, second))
		require.NotZero(t, first.(*smb2.FileStat).FileId)
		f, err := fs.Open(ctx, target)
		require.NoError(t, err)
		opened, statErr := f.Stat(ctx)
		closeErr := f.Close(ctx)
		require.NoError(t, statErr)
		require.NoError(t, closeErr)
		require.True(t, smb2.SameFile(first, opened))

		entries, err := fs.ReadDir(ctx, dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, first.(*smb2.FileStat).FileId, entries[0].(*smb2.FileStat).FileId)
		require.False(t, smb2.SameFile(first, entries[0]))

		link := join(dir, "link")
		err = fs.Symlink(ctx, "target", link)
		skipPermissionDenied(t, err)
		require.NoError(t, err)
		t.Run("follow_symlink", func(t *testing.T) {
			linked, err := fs.Stat(ctx, link)
			require.NoError(t, err)
			require.True(t, smb2.SameFile(first, linked))
			f, err := fs.Open(ctx, link)
			require.NoError(t, err)
			linkedOpen, statErr := f.Stat(ctx)
			closeErr := f.Close(ctx)
			require.NoError(t, statErr)
			require.NoError(t, closeErr)
			require.True(t, smb2.SameFile(first, linkedOpen))
		})
		linkInfo, err := fs.Lstat(ctx, link)
		require.NoError(t, err)
		require.False(t, smb2.SameFile(first, linkInfo))
		renamed := join(dir, "renamed")
		require.NoError(t, fs.Rename(ctx, target, renamed))
		moved, err := fs.Stat(ctx, renamed)
		require.NoError(t, err)
		require.True(t, smb2.SameFile(first, moved))
	})
}
