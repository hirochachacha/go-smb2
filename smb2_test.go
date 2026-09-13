// This package is used for integration testing.

package smb2_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	krbclient "github.com/go-krb5/krb5/client"
	krbconfig "github.com/go-krb5/krb5/config"
	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/stretchr/testify/require"
)

func join(ss ...string) string {
	return strings.Join(ss, `\`)
}

type transportConfig struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
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

type config struct {
	Name             string          `json:"name"`
	MaxCreditBalance uint16          `json:"max_credit_balance"`
	Transport        transportConfig `json:"transport"`
	Conn             connConfig      `json:"conn"`
	Session          sessionConfig   `json:"session"`
	TreeConn         treeConnConfig  `json:"tree_conn"`
}

// env holds the connection established from a single client_conf.json entry.
type env struct {
	cfg                config
	fs                 *smb2.Share
	rfs                *smb2.Share
	client             *smb2.Client
	destroyCredentials func()
}

var envs []*env

// loadEnvs connects to every entry in the configured client file. It returns
// nil when no configuration is available so that the integration tests are
// skipped.
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
		if e := connect(cfg); e != nil {
			es = append(es, e)
		}
	}
	return es
}

func connect(cfg config) *env {
	if cfg.Transport.Type != "tcp" {
		fmt.Println("unsupported transport type")
		return nil
	}

	var credentials smb2.Credentials
	var destroyCredentials func()
	switch cfg.Session.Type {
	case "ntlm":
		credentials = smb2.NTLMCredential{
			User:        cfg.Session.User,
			Password:    cfg.Session.Password,
			Domain:      cfg.Session.Domain,
			Workstation: cfg.Session.Workstation,
			TargetSPN:   cfg.Session.TargetSPN,
		}
	case "kerberos":
		krb5Config, err := krbconfig.Load(cfg.Session.KRB5Config)
		if err != nil {
			panic(err)
		}
		kclient := krbclient.NewWithPassword(cfg.Session.User, cfg.Session.Realm, cfg.Session.Password, krb5Config)
		if err := kclient.Login(); err != nil {
			kclient.Destroy()
			panic(err)
		}
		credentials = smb2.KerberosCredential{
			Client:    kclient,
			TargetSPN: cfg.Session.TargetSPN,
		}
		destroyCredentials = kclient.Destroy
	default:
		panic(fmt.Sprintf("unsupported session type %q", cfg.Session.Type))
	}

	client, err := smb2.NewClient(smb2.ClientConfig{
		Credentials: credentials,
		Transport: func(ctx context.Context, _ string) (smb2.Transport, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, cfg.Transport.Type, net.JoinHostPort(cfg.Transport.Host, strconv.Itoa(cfg.Transport.Port)))
			if err != nil {
				return nil, err
			}
			return smb2.NewDirectTCPTransport(conn), nil
		},
		MaxCreditBalance: cfg.MaxCreditBalance,
		Negotiator: smb2.Negotiator{
			RequireMessageSigning: cfg.Conn.RequireMessageSigning,
			SpecifiedDialect:      cfg.Conn.SpecifiedDialect,
		},
	})
	if err != nil {
		if destroyCredentials != nil {
			destroyCredentials()
		}
		panic(err)
	}

	ctx := context.Background()
	fs1, err := client.Mount(ctx, fmt.Sprintf(`\\%s\%s`, cfg.Transport.Host, cfg.TreeConn.Share1))
	if err != nil {
		client.Close()
		if destroyCredentials != nil {
			destroyCredentials()
		}
		panic(err)
	}

	fs2, err := client.Mount(ctx, fmt.Sprintf(`\\%s\%s`, cfg.Transport.Host, cfg.TreeConn.Share2))
	if err != nil {
		fs1.Unmount(ctx)
		client.Close()
		if destroyCredentials != nil {
			destroyCredentials()
		}
		panic(err)
	}

	return &env{
		cfg:                cfg,
		fs:                 fs1,
		rfs:                fs2,
		client:             client,
		destroyCredentials: destroyCredentials,
	}
}

func (e *env) close() {
	e.rfs.Unmount(context.Background())
	e.fs.Unmount(context.Background())
	e.client.Close()
	if e.destroyCredentials != nil {
		e.destroyCredentials()
	}
}

// forEachEnv runs f against every configured machine as a subtest.
func forEachEnv(t *testing.T, f func(t *testing.T, e *env)) {
	if len(envs) == 0 {
		t.Skip("client_conf.json is not configured")
	}
	for _, e := range envs {
		t.Run(e.cfg.Name, func(t *testing.T) {
			f(t, e)
		})
	}
}

func TestMain(m *testing.M) {
	envs = loadEnvs()
	code := m.Run()
	for _, e := range envs {
		e.close()
	}
	os.Exit(code)
}

func TestMkdirPreservesReadOnlyPermission(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestMkdirPreservesReadOnlyPermission", os.Getpid())
		readOnlyDir := join(testDir, "readOnly")
		if err := fs.Mkdir(context.Background(), testDir, 0o755); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = fs.Chmod(context.Background(), readOnlyDir, 0o755)
			_ = fs.RemoveAll(context.Background(), testDir)
		}()

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
		testDir := fmt.Sprintf("testDir-%d-TestReaddir", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
		testDir := fmt.Sprintf("testDir-%d-TestFile", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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

func TestSymlink(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestSymlink", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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

		if !os.IsPermission(err) {
			if err != nil {
				t.Skip("samba doesn't support reparse point")
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
		}
	})
}

func TestRelativeSymlink(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestRelativeSymlink", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
		if !os.IsPermission(err) {
			if err != nil {
				t.Skip("samba doesn't support reparse point")
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
		}
	})
}

func TestIsXXX(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestIsXXX", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
		if os.IsTimeout(err) {
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
		if os.IsTimeout(err) {
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
		if os.IsTimeout(err) {
			t.Error("unexpected error:", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		_, err = fs.Create(ctx, testDir+`\Exist`)
		if !os.IsTimeout(err) {
			t.Error("unexpected error:", err)
		}

		ctx, cancel = context.WithCancel(context.Background())
		cancel()
		_, err = fs.Create(ctx, testDir+`\Exist`)
		if os.IsTimeout(err) {
			t.Error("unexpected error:", err)
		}
	})
}

func TestRename(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestRename", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
		if os.IsExist(err) {
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
		testDir := fmt.Sprintf("testDir-%d-TestChtimes", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
		testDir := fmt.Sprintf("testDir-%d-TestChmod", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
		testDir := fmt.Sprintf("testDir-%d-TestRemoveReadOnlyFile", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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

func TestListShareNames(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		cfg := e.cfg
		names, err := e.client.ListShareNames(context.Background(), cfg.Transport.Host)
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

func TestServerSideCopy(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestServerSideCopy", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

		err = fs.WriteFile(context.Background(), join(testDir, "src.txt"), []byte("hello world!"), 0o666)
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
		testDir := fmt.Sprintf("testDir-%d-TestRemoveAll", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		err = fs.WriteFile(context.Background(), join(testDir, "hello.txt"), []byte("hello world!"), 0o666)
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

func TestContextCancellation(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		cfg := e.cfg
		ctx, cancel := context.WithCancel(context.Background())

		cancelShare, err := e.client.Mount(context.Background(), fmt.Sprintf(`\\%s\%s`, cfg.Transport.Host, cfg.TreeConn.Share1))
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

		_, err = e.client.Mount(ctx, fmt.Sprintf(`\\%s\somewhere`, cfg.Transport.Host))
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
		testDir := fmt.Sprintf("testDir-%d-TestGlob", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

		for _, dir := range []string{"", "dir1", "dir2", "dir3"} {
			if dir != "" {
				err = fs.Mkdir(context.Background(), join(testDir, dir), 0o755)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, file := range []string{"abc.ext", "ab1.ext", "ab9.ext", "test", "tes"} {
				err = fs.WriteFile(context.Background(), join(testDir, dir, file), []byte("hello world!"), 0o666)
				if err != nil {
					t.Fatal(err)
				}
			}
		}

		matches1, err := fs.Glob(context.Background(), join(testDir, "ab[0-9].ext"))
		if err != nil {
			t.Fatal(err)
		}
		expected1 := []string{join(testDir, "ab1.ext"), join(testDir, "ab9.ext")}

		if !reflect.DeepEqual(matches1, expected1) {
			t.Errorf("unexpected matches: %v != %v", matches1, expected1)
		}

		matches2, err := fs.Glob(context.Background(), join(testDir, "tes?"))
		if err != nil {
			t.Fatal(err)
		}
		expected2 := []string{join(testDir, "test")}

		if !reflect.DeepEqual(matches2, expected2) {
			t.Errorf("unexpected matches: %v != %v", matches2, expected2)
		}

		matches3, err := fs.Glob(context.Background(), join(testDir, "dir[0-2]/ab[0-9].ext"))
		if err != nil {
			t.Fatal(err)
		}
		expected3 := []string{join(testDir, "dir1", "ab1.ext"), join(testDir, "dir1", "ab9.ext"), join(testDir, "dir2", "ab1.ext"), join(testDir, "dir2", "ab9.ext")}

		if !reflect.DeepEqual(matches3, expected3) {
			t.Errorf("unexpected matches: %v != %v", matches3, expected3)
		}

		matches4, err := fs.Glob(context.Background(), join(testDir, "*/ab[0-9].ext"))
		if err != nil {
			t.Fatal(err)
		}
		expected4 := []string{join(testDir, "dir1", "ab1.ext"), join(testDir, "dir1", "ab9.ext"), join(testDir, "dir2", "ab1.ext"), join(testDir, "dir2", "ab9.ext"), join(testDir, "dir3", "ab1.ext"), join(testDir, "dir3", "ab9.ext")}

		if !reflect.DeepEqual(matches4, expected4) {
			t.Errorf("unexpected matches: %v != %v", matches4, expected4)
		}

		matches5, err := fs.Glob(context.Background(), join(testDir, "*/abcd"))
		if err != nil {
			t.Fatal(err)
		}
		var expected5 []string

		if !reflect.DeepEqual(matches5, expected5) {
			t.Errorf("unexpected matches: %v != %v", matches5, expected5)
		}
	})
}

func TestEcho(t *testing.T) {
	t.Skip("Echo is no longer part of the public Client API")
}

func TestFileEdgeCases(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestFileEdgeCases", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
		testDir := fmt.Sprintf("testDir-%d-TestDirEdgeCases", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

		// 1. MkdirAll deeply nested
		deepPath := join(testDir, "sub1", "sub2", "sub3", "sub4")
		err = fs.MkdirAll(context.Background(), deepPath, 0o755)
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
		testDir := fmt.Sprintf("testDir-%d-TestRenameEdgeCases", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

		// 1. Move file into subfolder
		subDir := join(testDir, "subdir")
		err = fs.Mkdir(context.Background(), subDir, 0o755)
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
		testDir := fmt.Sprintf("testDir-%d-TestLargeFileCopy", os.Getpid())
		err := fs.Mkdir(context.Background(), testDir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
		testDir := fmt.Sprintf("testDir-%d-TestWaitForChange", os.Getpid())
		if err := fs.Mkdir(context.Background(), testDir, 0o755); err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

		type outcome struct {
			res smb2.ChangeResult
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
				res, err := d.WaitForChange(ctx, smb2.ChangeFileName, false)
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
				res, err := d.WaitForChange(ctx, smb2.ChangeFileName, true)
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
				res, err := d.WaitForChange(ctx, smb2.ChangeFileName, false)
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

			_, err = f.WaitForChange(context.Background(), smb2.ChangeFileName, false)
			if !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("expected os.ErrInvalid on regular file, got: %v", err)
			}
		})

		t.Run("LockedParameters", func(t *testing.T) {
			d, err := fs.Open(context.Background(), testDir)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close(context.Background())

			ctx, cancel := context.WithCancel(context.Background())
			cancel() // already canceled

			// First call establishes the filter and recursive.
			_, _ = d.WaitForChange(ctx, smb2.ChangeFileName, false)

			// Conflicting recursive
			_, err = d.WaitForChange(context.Background(), smb2.ChangeFileName, true)
			if !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("expected os.ErrInvalid on recursive conflict, got: %v", err)
			}

			// Conflicting filter
			_, err = d.WaitForChange(context.Background(), smb2.ChangeDirName, false)
			if !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("expected os.ErrInvalid on filter conflict, got: %v", err)
			}
		})
	})
}

func TestFileLock(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestFileLock", os.Getpid())
		if err := fs.Mkdir(context.Background(), testDir, 0o755); err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

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
			if _, ok := errors.AsType[*smb2.ResponseError](err); !ok {
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
		testDir := fmt.Sprintf("testDir-%d-TestSecurityDescriptor", os.Getpid())
		if err := fs.Mkdir(context.Background(), testDir, 0o755); err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(context.Background(), testDir)

		filePath := join(testDir, "sec.txt")
		f, err := fs.Create(context.Background(), filePath)
		if err != nil {
			t.Fatal(err)
		}
		f.Close(context.Background())

		checkSupported := func(t *testing.T, err error) {
			t.Helper()
			var rerr *smb2.ResponseError
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
				var rerr *smb2.ResponseError
				if errors.As(err, &rerr) && rerr.Code == 0xC0000022 /* STATUS_ACCESS_DENIED */ {
					t.Skip("account is not permitted to set the DACL")
				}
				t.Fatalf("failed to set DACL: %v", err)
			}
		})
	})
}
