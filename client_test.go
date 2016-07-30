package smb2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"

	// "github.com/davecgh/go-spew/spew"

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

func TestClient(t *testing.T) {
	var cfg config

	cf, err := os.Open(".client_test.conf.json")
	if err != nil {
		fmt.Println("cannot open .client_test.conf.json")
		t.Skip()
	}

	err = json.NewDecoder(cf).Decode(&cfg)
	if err != nil {
		fmt.Println("cannot decode .client_test.conf.json")
		t.Skip()
	}

	if cfg.Transport.Type != "tcp" {
		fmt.Println("unsupported transport type")
		t.Skip()
	}

	conn, err := net.Dial(cfg.Transport.Type, fmt.Sprintf("%s:%d", cfg.Transport.Host, cfg.Transport.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if cfg.Session.Type != "ntlm" {
		fmt.Println("unsupported session type")
		t.Skip()
	}

	d := &Dialer{
		MaxCreditBalance: cfg.MaxCreditBalance,
		Negotiator: Negotiator{
			RequireMessageSigning: cfg.Conn.RequireMessageSigning,
			SpecifiedDialect:      cfg.Conn.SpecifiedDialect,
		},
		Initiator: &NTLMInitiator{
			User:        cfg.Session.User,
			Password:    cfg.Session.Password,
			Domain:      cfg.Session.Domain,
			Workstation: cfg.Session.Workstation,
			TargetSPN:   cfg.Session.TargetSPN,
		},
	}

	if guid, err := hex.DecodeString(cfg.Conn.ClientGuid); err == nil {
		copy(d.Negotiator.ClientGuid[:], guid)
	}

	switch cfg.Conn.SpecifiedDialect {
	case 202:
		d.Negotiator.SpecifiedDialect = 0x202
	case 210:
		d.Negotiator.SpecifiedDialect = 0x210
	case 300:
		d.Negotiator.SpecifiedDialect = 0x300
	case 302:
		d.Negotiator.SpecifiedDialect = 0x302
	case 311:
		d.Negotiator.SpecifiedDialect = 0x311
	default:
		fmt.Println("unsupported dialect")
		t.Skip()
	}

	c, err := d.Dial(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Logoff()

	fs, err := c.Mount(cfg.TreeConn.Share)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Umount()

	testDir := fmt.Sprintf("testDir%d", rand.Int())

	// fs.RemoveAll(testDir)

	err = fs.Mkdir(testDir, 0755)
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

	n64, err := f.Seek(0, os.SEEK_SET)
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

	n64, err = f.Seek(-3, os.SEEK_END)
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

	err = fs.Symlink(testDir+`\testFile`, testDir+`\linkToTestFile`)
	if !IsPermission(err) {
		if err != nil {
			t.Fatal(err)
		}
		defer fs.Remove(testDir + `\linkToTestFile`)

		stat, err = fs.Lstat(testDir + `\linkToTestFile`)
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

	f, err = fs.Create(testDir + `\Exist`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\Exist`)
	defer f.Close()

	_, err = fs.OpenFile(testDir+`\Exist`, os.O_CREATE|os.O_EXCL, 0666)
	if !IsExist(err) {
		t.Error("unexpected error:", err)
	}

	_, err = fs.Open(testDir + `\notExist`)
	if !IsNotExist(err) {
		t.Error("unexpected error:", err)
	}

	f, err = fs.Create(testDir + `\old`)
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

	_, err = fs.Stat(testDir + `\new`)
	if IsNotExist(err) {
		t.Error("unexpected error:", err)
	}
}
