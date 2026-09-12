smb2
====

[![Build Status](https://github.com/hirochachacha/go-smb2/actions/workflows/go.yml/badge.svg)](https://github.com/hirochachacha/go-smb2/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/hirochachacha/go-smb2.svg)](https://pkg.go.dev/github.com/hirochachacha/go-smb2)

Description
-----------

SMB2/3 client implementation.

Installation
------------

Requires Go 1.26 or later.

`go get github.com/hirochachacha/go-smb2`

Documentation
-------------

http://godoc.org/github.com/hirochachacha/go-smb2

Examples
--------

### List share names ###

```go
package main

import (
	"fmt"
	"net"

	"github.com/hirochachacha/go-smb2"
)

func main() {
	conn, err := net.Dial("tcp", "SERVERNAME:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	names, err := s.ListShareNames()
	if err != nil {
		panic(err)
	}

	for _, name := range names {
		fmt.Println(name)
	}
}
```

### Kerberos authentication ###

`KerberosInitiator` uses [go-krb5/krb5](https://github.com/go-krb5/krb5)
with AES mutual authentication. Supply an authenticated client and the
registered `cifs/<server FQDN>` SPN:

```go
package main

import (
    "context"
    "net"
    "os"
    "time"

    "github.com/go-krb5/krb5/client"
    "github.com/go-krb5/krb5/config"
    "github.com/hirochachacha/go-smb2"
)

func main() {
    cfg, err := config.Load("/etc/krb5.conf")
    if err != nil {
        panic(err)
    }
    cl := client.NewWithPassword("USERNAME", "EXAMPLE.COM", os.Getenv("KRB5_PASSWORD"), cfg)
    defer cl.Destroy()
    if err := cl.Login(); err != nil {
        panic(err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "server.example.com:445")
    if err != nil {
        panic(err)
    }
    defer conn.Close()
    d := smb2.Dialer{
        Initiator: &smb2.KerberosInitiator{
            Client: cl,
            TargetSPN: "cifs/server.example.com",
        },
        Negotiator: smb2.Negotiator{RequireMessageSigning: true},
    }
    session, err := d.DialContext(ctx, conn)
    if err != nil {
        panic(err)
    }
    defer session.Logoff()

    share, err := session.WithContext(ctx).Mount("share")
    if err != nil {
        panic(err)
    }
    defer share.Umount()
}
```

You can also supply a client created with `client.NewWithKeytab` (call
`Login` first) or `client.NewFromCCache`. Credential loading, renewal and
client cleanup belong to the caller. Use a separate initiator for each
concurrent handshake. KDC exchanges use the Kerberos client's timeouts;
its ticket API does not accept the SMB `DialContext` context.

Custom implementations of `Initiator` must return an error from `Sum`,
implement `VerifySum`, and report mechanism completion through `Complete`.
An empty final SPNEGO token does not by itself complete mutual authentication.

The integration test environment provisions a disposable Samba AD domain,
KDC, NTLM account, and plain, read-only, and encrypted SMB shares with Docker
Compose. It runs both the NTLM file-operation suite and the Kerberos suite.
Docker Engine with the Compose plugin, or Docker Desktop on macOS, is
required:

```sh
./test/integration/run.sh
```

The script builds the test server, waits until it is healthy, runs the test,
and removes the container and volumes. It binds Kerberos to local port 1088
and SMB to local port 1445. The Go tests run on the host, so running this on
macOS with Docker Desktop exercises the native macOS client against the Linux
Samba server. GitHub Actions runs this integration environment on Linux;
separate native Windows and macOS jobs run the remaining test suite.

To test another Kerberos environment, set `SMB2_KRB5_CONFIG` (krb5.conf
path), `SMB2_KRB5_USER`, `SMB2_KRB5_REALM`, `SMB2_KRB5_PASSWORD`,
`SMB2_KRB5_ADDR` (host:port), `SMB2_KRB5_SPN`, `SMB2_KRB5_SHARE`, and
`SMB2_KRB5_ENCRYPTED_SHARE`, then run:

```sh
go test -race -run '^TestKerberosIntegration$' -v .
```

### File manipulation ###

```go
package main

import (
	"io"
	"io/ioutil"
	"net"

	"github.com/hirochachacha/go-smb2"
)

func main() {
	conn, err := net.Dial("tcp", "SERVERNAME:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	fs, err := s.Mount("SHARENAME")
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	f, err := fs.Create("hello.txt")
	if err != nil {
		panic(err)
	}
	defer fs.Remove("hello.txt")
	defer f.Close()

	_, err = f.Write([]byte("Hello world!"))
	if err != nil {
		panic(err)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		panic(err)
	}

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))
}
```

### Check error types ###

```go
package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/hirochachacha/go-smb2"
)

func main() {
	conn, err := net.Dial("tcp", "SERVERNAME:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	fs, err := s.Mount("SHARENAME")
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	_, err = fs.Open("notExist.txt")

	fmt.Println(os.IsNotExist(err)) // true
	fmt.Println(os.IsExist(err))    // false

	fs.WriteFile("hello2.txt", []byte("test"), 0444)
	err = fs.WriteFile("hello2.txt", []byte("test2"), 0444)
	fmt.Println(os.IsPermission(err)) // true

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	_, err = fs.WithContext(ctx).Open("hello.txt")

	fmt.Println(os.IsTimeout(err)) // true
}
```

When an idle connection has too few credits for a compound operation, the
client sends its requests sequentially using the opened handle. If a single
request itself exceeds the credits available on an idle connection, it returns
an `InternalError` instead of waiting for an unrelated operation to replenish
credits. Requests still wait when another request is in flight.

### Glob and WalkDir through FS interface ###

```go
package main

import (
	"fmt"
	"net"
	iofs "io/fs"

	"github.com/hirochachacha/go-smb2"
)

func main() {
	conn, err := net.Dial("tcp", "SERVERNAME:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	fs, err := s.Mount("SHARENAME")
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	matches, err := iofs.Glob(fs.DirFS("."), "*")
	if err != nil {
		panic(err)
	}
	for _, match := range matches {
		fmt.Println(match)
	}

	err = iofs.WalkDir(fs.DirFS("."), ".", func(path string, d iofs.DirEntry, err error) error {
		fmt.Println(path, d, err)

		return nil
	})
	if err != nil {
		panic(err)
	}
}
```
