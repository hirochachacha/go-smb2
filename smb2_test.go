package smb2_test

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"sort"
	"time"

	"github.com/hirochachacha/go-smb2"

	"testing"
)

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
	TargetSPN   string `json:"targetSPN"`
}

type treeConnConfig struct {
	Share string `json:"share"`
}

type config struct {
	MaxCreditBalance uint16          `json:"max_credit_balance"`
	Transport        transportConfig `json:"transport"`
	Conn             connConfig      `json:"conn,omitempty"`
	Session          sessionConfig   `json:"session,omitempty"`
	TreeConn         treeConnConfig  `json:"tree_conn"`
}

var fs *smb2.Share
var session *smb2.Session

func connect(f func()) {
	{
		var cfg config

		cf, err := os.Open("client_conf.json")
		if err != nil {
			fmt.Println("cannot open client_conf.json")
			goto NO_CONNECTION
		}

		err = json.NewDecoder(cf).Decode(&cfg)
		if err != nil {
			fmt.Println("cannot decode client_conf.json")
			goto NO_CONNECTION
		}

		if cfg.Transport.Type != "tcp" {
			fmt.Println("unsupported transport type")
			goto NO_CONNECTION
		}

		conn, err := net.Dial(cfg.Transport.Type, fmt.Sprintf("%s:%d", cfg.Transport.Host, cfg.Transport.Port))
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		if cfg.Session.Type != "ntlm" {
			panic("unsupported session type")
		}

		dialer := &smb2.Dialer{
			MaxCreditBalance: cfg.MaxCreditBalance,
			Negotiator: smb2.Negotiator{
				RequireMessageSigning: cfg.Conn.RequireMessageSigning,
				SpecifiedDialect:      cfg.Conn.SpecifiedDialect,
			},
			Initiator: &smb2.NTLMInitiator{
				User:        cfg.Session.User,
				Password:    cfg.Session.Password,
				Domain:      cfg.Session.Domain,
				Workstation: cfg.Session.Workstation,
				TargetSPN:   cfg.Session.TargetSPN,
			},
		}

		c, err := dialer.Dial(conn)
		if err != nil {
			panic(err)
		}
		defer c.Logoff()

		fs1, err := c.Mount(cfg.TreeConn.Share)
		if err != nil {
			panic(err)
		}
		defer fs1.Umount()

		fs = fs1
		session = c
	}
NO_CONNECTION:
	f()
}

func TestMain(m *testing.M) {
	var code int
	connect(func() {
		code = m.Run()
	})
	os.Exit(code)
}

func TestReaddir(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestReaddir", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir)

	d, err := fs.Open(testDir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	fi, err := d.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(fi) != 0 {
		t.Error("unexpected content length:", len(fi))
	}

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\testFile`)
	defer f.Close()

	d2, err := fs.Open(testDir)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()

	fi2, err := d2.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(fi2) != 1 {
		t.Error("unexpected content length:", len(fi2))
	}

	fi2, err = d2.Readdir(1)
	if err != io.EOF {
		t.Error("unexpected error: ", err)
	}
}

func TestFile(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestFile", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir)

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\testFile`)
	defer f.Close()

	if f.Name() != testDir+`\testFile` {
		t.Error("unexpected name:", f.Name())
	}

	n, err := f.Write([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	if n != 4 {
		t.Error("unexpected content length:", n)
	}

	n, err = f.Write([]byte("Content"))
	if err != nil {
		t.Fatal(err)
	}

	if n != 7 {
		t.Error("unexpected content length:", n)
	}

	n64, err := f.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatal(err)
	}

	if n64 != 0 {
		t.Error("unexpected seek length:", n64)
	}

	p := make([]byte, 10)

	n, err = f.Read(p)
	if err != nil {
		t.Fatal(err)
	}

	if n != 10 {
		t.Error("unexpected content length:", n)
	}

	if string(p) != "testConten" {
		t.Error("unexpected content:", string(p))
	}

	stat, err := f.Stat()
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

	f.Truncate(4)

	n64, err = f.Seek(-3, io.SeekEnd)
	if err != nil {
		t.Fatal(err)
	}

	if n64 != 1 {
		t.Error("unexpected seek length:", n64)
	}

	n, err = f.Read(p)
	if err != nil {
		t.Fatal(err)
	}

	if n != 3 {
		t.Error("unexpected content length:", n)
	}

	if string(p[:n]) != "est" {
		t.Error("unexpected content:", string(p))
	}
}

func TestSymlink(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestSymlink", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir)

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\testFile`)
	defer f.Close()

	_, err = f.Write([]byte("testContent"))
	if err != nil {
		t.Fatal(err)
	}

	err = fs.Symlink(testDir+`\testFile`, testDir+`\linkToTestFile`)

	if !smb2.IsPermission(err) {
		if err != nil {
			t.Skip("samba doesn't support reparse point")
		}
		defer fs.Remove(testDir + `\linkToTestFile`)

		stat, err := fs.Lstat(testDir + `\linkToTestFile`)
		if err != nil {
			t.Fatal(err)
		}

		if stat.Name() != `linkToTestFile` {
			t.Error("unexpected name:", stat.Name())
		}

		if stat.Mode()&os.ModeSymlink == 0 {
			t.Error("should be a symlink")
		}

		target, err := fs.Readlink(testDir + `\linkToTestFile`)
		if err != nil {
			t.Fatal(err)
		}

		if target != testDir+`\testFile` {
			t.Error("unexpected target:", target)
		}

		f, err = fs.Open(testDir + `\linkToTestFile`)
		if err == nil { // if it supports follow-symlink
			bs, err := ioutil.ReadAll(f)
			if err != nil {
				t.Fatal(err)
			}
			if string(bs) != "testContent" {
				t.Error("unexpected content:", string(bs))
			}
		}
	}
}

func TestIsXXX(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestIsXXX", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir)

	f, err := fs.Create(testDir + `\Exist`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\Exist`)
	defer f.Close()

	_, err = fs.OpenFile(testDir+`\Exist`, os.O_CREATE|os.O_EXCL, 0666)
	if !smb2.IsExist(err) {
		t.Error("unexpected error:", err)
	}

	_, err = fs.Open(testDir + `\notExist`)
	if !smb2.IsNotExist(err) {
		t.Error("unexpected error:", err)
	}

}

func TestRename(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestRename", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir)

	f, err := fs.Create(testDir + `\old`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("testContent"))
	if err != nil {
		t.Fatal(err)
	}
	err = f.Close()
	if err != nil {
		fs.Remove(testDir + `\old`)

		t.Fatal(err)
	}

	err = fs.Rename(testDir+`\old`, testDir+`\new`)
	if err != nil {
		fs.Remove(testDir + `\old`)

		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\new`)

	_, err = fs.Stat(testDir + `\old`)
	if smb2.IsExist(err) {
		t.Error("unexpected error:", err)
	}
	f, err = fs.Open(testDir + `\new`)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(bs) != "testContent" {
		t.Error("unexpected content:", string(bs))
	}
}

func TestChtimes(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestChtimes", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir)

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Close()
	if err != nil {
		fs.Remove(testDir + `\testFile`)

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

	err = fs.Chtimes(testDir+`\testFile`, atime, mtime)
	if err != nil {
		t.Fatal(err)
	}

	stat, err := fs.Stat(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}

	if !stat.ModTime().Equal(mtime) {
		t.Error("unexpected mtime:", stat.ModTime())
	}
}

func TestChmod(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestChmod", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir)

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(testDir + `\testFile`)
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode() != 0666 {
		t.Error("unexpected mode:", stat.Mode())
	}
	err = f.Chmod(0444)
	if err != nil {
		t.Fatal(err)
	}
	stat, err = f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode() != 0444 {
		t.Error("unexpected mode:", stat.Mode())
	}
}

func TestListShareNames(t *testing.T) {
	if session == nil {
		t.Skip()
	}
	names, err := session.ListShareNames()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)

	if !reflect.DeepEqual(names, []string{"IPC$", "tmp"}) {
		t.Error("unexpected share names:", names)
	}
}
