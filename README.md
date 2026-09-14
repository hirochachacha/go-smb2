smb2
====

[![Build Status](https://github.com/hirochachacha/go-smb2/actions/workflows/go.yml/badge.svg)](https://github.com/hirochachacha/go-smb2/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/hirochachacha/go-smb2/v2.svg)](https://pkg.go.dev/github.com/hirochachacha/go-smb2/v2)

Description
-----------

SMB2/3 client implementation.

Installation
------------

Requires Go 1.26 or later.

`go get github.com/hirochachacha/go-smb2/v2`

Documentation
-------------

http://godoc.org/github.com/hirochachacha/go-smb2/v2

Examples
--------

### File manipulation ###

```go
package main

import (
	"context"
	"fmt"
	"io"

	"github.com/hirochachacha/go-smb2/v2"
)

func main() {
	client := smb2.NewClient(smb2.ClientConfig{
		Credentials: smb2.NTLMCredential{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
		TransportDialer: smb2.TCPDialer{},
	})
	defer client.Close()

	ctx := context.Background()
	fs, err := client.Mount(ctx, `\\SERVERNAME\SHARENAME`)
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
}
```

### List share names ###

```go
package main

import (
	"context"
	"fmt"

	"github.com/hirochachacha/go-smb2/v2"
)

func main() {
	client := smb2.NewClient(smb2.ClientConfig{
		Credentials: smb2.NTLMCredential{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
		TransportDialer: smb2.TCPDialer{},
	})
	defer client.Close()

	names, err := client.ListShareNames(context.Background(), "SERVERNAME")
	if err != nil {
		panic(err)
	}

	for _, name := range names {
		fmt.Println(name)
	}
}
```

### Glob and WalkDir through FS interface ###

```go
package main

import (
	"context"
	"fmt"
	iofs "io/fs"

	"github.com/hirochachacha/go-smb2/v2"
)

func main() {
	client := smb2.NewClient(smb2.ClientConfig{
		Credentials: smb2.NTLMCredential{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
		TransportDialer: smb2.TCPDialer{},
	})
	defer client.Close()

	fs, err := client.Mount(context.Background(), `\\SERVERNAME\SHARENAME`)
	if err != nil {
		panic(err)
	}
	defer fs.Unmount(context.Background())

	bound := fs.WithContext(context.Background())
	matches, err := iofs.Glob(bound, "*")
	if err != nil {
		panic(err)
	}
	for _, match := range matches {
		fmt.Println(match)
	}

	err = iofs.WalkDir(bound, ".", func(path string, d iofs.DirEntry, err error) error {
		fmt.Println(path, d, err)

		return nil
	})
	if err != nil {
		panic(err)
	}
}
```

### Check error types ###

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/hirochachacha/go-smb2/v2"
)

func main() {
	client := smb2.NewClient(smb2.ClientConfig{
		Credentials: smb2.NTLMCredential{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
		TransportDialer: smb2.TCPDialer{},
	})
	defer client.Close()

	fs, err := client.Mount(context.Background(), `\\SERVERNAME\SHARENAME`)
	if err != nil {
		panic(err)
	}
	defer fs.Unmount(context.Background())

	_, err = fs.Open(context.Background(), "notExist.txt")

	fmt.Println(errors.Is(err, os.ErrNotExist)) // true
	fmt.Println(errors.Is(err, os.ErrExist))    // false

	fs.WriteFile(context.Background(), "hello2.txt", []byte("test"), 0444)
	err = fs.WriteFile(context.Background(), "hello2.txt", []byte("test2"), 0444)
	fmt.Println(errors.Is(err, os.ErrPermission)) // true

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	_, err = fs.Open(ctx, "hello.txt")

	fmt.Println(errors.Is(err, context.ErrDeadlineExceeded)) // true
}
```

When an idle connection has too few credits for a compound operation, the
client sends its requests sequentially using the opened handle. If a single
request itself exceeds the credits available on an idle connection, it returns
an `InternalError` instead of waiting for an unrelated operation to replenish
credits. Requests still wait when another request is in flight.

### Kerberos authentication ###

`KerberosCredential` uses [go-krb5/krb5](https://github.com/go-krb5/krb5)
with AES mutual authentication. Supply an authenticated Kerberos client;
`NewClient` derives the registered `cifs/<server FQDN>` SPN from the UNC
server name:

```go
package main

import (
    "context"
    "os"
    "time"

    krb5client "github.com/go-krb5/krb5/client"
    krb5config "github.com/go-krb5/krb5/config"
    "github.com/hirochachacha/go-smb2/v2"
)

func main() {
    cfg, err := krb5config.Load("/etc/krb5.conf")
    if err != nil {
        panic(err)
    }
    kcl := krb5client.NewWithPassword("USERNAME", "EXAMPLE.COM", os.Getenv("KRB5_PASSWORD"), cfg)
    defer kcl.Destroy()
    if err := kcl.Login(); err != nil {
        panic(err)
    }

    client := smb2.NewClient(smb2.ClientConfig{
        Credentials:           smb2.KerberosCredential{Client: kcl},
        TransportDialer:       smb2.TCPDialer{},
        RequireMessageSigning: true,
    })
    defer client.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    share, err := client.Mount(ctx, `\\server.example.com\share`)
    if err != nil {
        panic(err)
    }
    defer share.Unmount(ctx)
}
```

You can also supply a client created with `client.NewWithKeytab` (call
`Login` first) or `client.NewFromCCache`. Credential loading, renewal and
client cleanup belong to the caller. KDC exchanges use the Kerberos client's
timeouts; its ticket API does not accept the `Client.Mount` context.

Custom implementations of `Credentials` must return a fresh `Initiator` for
each call. Custom initiators must implement `GetMIC` and `VerifyMIC`, and
report mechanism completion through `Complete`.
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

The DFS integration suite uses this namespace:

| Namespace path | Referral target |
| --- | --- |
| `\\127.0.0.1\dfs\link` | `\\127.0.0.2\dfs-target` |
| `\\127.0.0.1\dfs\link-alias` | `\\127.0.0.2\dfs-target` |
| `\\127.0.0.1\dfs\link-extra` | `\\127.0.0.3\dfs-encrypted\nested` |
| `\\127.0.0.1\dfs\link-chain` | `\\127.0.0.2\dfs-hop\入口` |
| `\\127.0.0.2\dfs-hop\入口` | `\\127.0.0.3\dfs-hop2\出口` |
| `\\127.0.0.3\dfs-hop2\出口` | `\\127.0.0.3\dfs-encrypted\nested` |
| `\\127.0.0.1\dfs\link-cycle` | `\\127.0.0.2\dfs-hop\cycle` |
| `\\127.0.0.2\dfs-hop\cycle` | `\\127.0.0.1\dfs\link-cycle` |

The three server names use separate client connections to the same Samba
daemon, with `127.0.0.2` and `127.0.0.3` registered as Samba NetBIOS aliases
so each accepts referral queries. `dfs-encrypted` requires SMB encryption.
Tests cover Unicode paths,
target subdirectories, similarly named link prefixes, renames across aliases,
rejection of cross-target renames, concurrent first referrals, and keeping
another mount's open file usable after unmounting a shared target.
The three-hop chain checks cold and cached reads, large files, and renames
through a different link to the same final share. The cycle test verifies
that resolution fails promptly and the connection remains usable. Resolution
also has an implementation limit of 32 referrals per operation.

`run.sh` provisions and runs these cases. To run against the local Samba VM:

```sh
SMB2_DFS_ADDR=127.0.0.1:445 \
SMB2_DFS_SERVER=127.0.0.1 \
SMB2_DFS_TARGET_SERVER=127.0.0.2 \
SMB2_DFS_SECOND_TARGET_SERVER=127.0.0.3 \
SMB2_DFS_USER=smbuser \
SMB2_DFS_PASSWORD='Smbpasswd12345' \
SMB2_DFS_DOMAIN=SMB2TEST \
SMB2_DFS_SHARE=dfs \
SMB2_DFS_LINK=link \
CGO_ENABLED=1 go test -race -count=1 -run '^TestDFSIntegration$' -v .
```

For servers at separate endpoints, set `SMB2_DFS_TARGET_ADDR` and
`SMB2_DFS_SECOND_TARGET_ADDR` to their `host:port` addresses; both default to
`SMB2_DFS_ADDR`. The namespace must provide the configured link, its
`-alias`, `-extra`, `-chain`, and `-cycle` siblings, and the intermediate
namespaces and target shares shown above.

To test another Kerberos environment, set `SMB2_KRB5_CONFIG` (krb5.conf
path), `SMB2_KRB5_USER`, `SMB2_KRB5_REALM`, `SMB2_KRB5_PASSWORD`,
`SMB2_KRB5_ADDR` (host:port), `SMB2_KRB5_SPN`, `SMB2_KRB5_SHARE`, and
`SMB2_KRB5_ENCRYPTED_SHARE`, then run:

```sh
go test -race -run '^TestKerberosIntegration$' -v .
```

### SMB over QUIC ###

`QUICDialer` connects to SMB over QUIC (UDP port 443 by default). It uses
the `smb` ALPN and requires SMB 3.1.1. A nil TLS configuration uses the
system trust roots. Supply a CA pool when the server certificate is not
trusted by the system:

```go
client := smb2.NewClient(smb2.ClientConfig{
    Credentials: smb2.NTLMCredential{User: "USERNAME", Password: "PASSWORD"},
    TransportDialer: smb2.QUICDialer{
        TLSConfig: &tls.Config{
            RootCAs: roots,
        },
    },
})
defer client.Close()
```

The integration tests accept `tcp` or `quic` in `client_conf.json`'s
`transport.type`. For QUIC, configure the UDP endpoint and optional TLS
settings:

```json
"transport": {
  "type": "quic",
  "host": "127.0.0.1",
  "port": 443,
  "tls": {
    "server_name": "samba.smb2.test",
    "ca_file": "/home/hiro.guest/.config/smb-quic/ca.pem"
  }
}
```

`host` and `port` select the network endpoint. `tls.server_name` selects the
certificate name and SNI; when omitted, the endpoint host is used.
`tls.ca_file` is a PEM CA bundle used as the trust roots; when omitted,
system roots are used. Relative file paths resolve from the test process's
working directory. Certificate verification is enabled. Set `conn.dialect`
to `785` (SMB 3.1.1), or omit it to let the QUIC transport select it.
The existing `session` and `tree_conn` settings apply to QUIC as well.

The supplied configuration includes `samba-quic-plain` and
`samba-quic-aes256-gcm` for the local Samba environment. Run it with:

```sh
SMB2_CLIENT_CONFIG=client_conf.json go test -count=1 -v .
```

Tests connect to every entry in the selected file. To test only QUIC,
use a configuration file containing only the QUIC entries.
