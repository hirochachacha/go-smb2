smb2
====

[![Build Status](https://github.com/hirochachacha/go-smb2/actions/workflows/go.yml/badge.svg)](https://github.com/hirochachacha/go-smb2/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/hirochachacha/go-smb2/v2.svg)](https://pkg.go.dev/github.com/hirochachacha/go-smb2/v2)

Description
-----------

SMB2/3 client implementation for Go.

Features
--------

- **Dialects**: SMB 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1.
- **Transports**: Direct TCP and SMB over QUIC (requires SMB 3.1.1).
- **Authentication**: NTLMv2 and Kerberos.
- **Encryption**: Transparent encryption via AES-128-CCM (SMB 3.0+) and AES-128-GCM / AES-256-CCM / AES-256-GCM (SMB 3.1.1).
- **Zero-Copy I/O**: Zero-copy reads and writes for unencrypted and uncompressed traffic.
- **Symlinks**: Symbolic link evaluation and creation via NTFS reparse points.
- **DFS**: Automatic Distributed File System (DFS) referral resolution.
- **Go Integration**: `io/fs` interface support and `context.Context` cancellation across all operations.

Installation
------------

Requires Go 1.26 or later.

`go get github.com/hirochachacha/go-smb2/v2`

Documentation
-------------

http://godoc.org/github.com/hirochachacha/go-smb2/v2

Examples
--------

A `smb2.Dialer` creates an independent `Session` for each `Dial` call. Mount a
share by name; its operations take share-relative paths. `Share.Unmount`
disconnects that tree, while `Session.Close` closes the connection and invalidates
all its Shares and Files. The Dialer owns no connections and needs no Close.
Do not modify its configuration while it is in use, including by a DFS client.

For transparent DFS and cross-server symbolic links, use `dfs.New(dialer)`.
Its path operations take absolute UNCs and it owns and reuses Sessions and Shares
until `Client.Close`, including sessions used only to retrieve referrals. Close
cancels connection establishment and invalidates open Files. Custom credential
and transport factories must cooperate with context cancellation.

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
	dialer := &smb2.Dialer{
		Credentials: smb2.NTLMCredential{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
	}

	ctx := context.Background()
	session, err := dialer.Dial(ctx, "SERVERNAME")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	fs, err := session.Mount(ctx, "SHARENAME")
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
	dialer := &smb2.Dialer{
		Credentials: smb2.NTLMCredential{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
	}

	session, err := dialer.Dial(context.Background(), "SERVERNAME")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	names, err := session.ListShareNames(context.Background())
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
	dialer := &smb2.Dialer{
		Credentials: smb2.NTLMCredential{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
	}

	session, err := dialer.Dial(context.Background(), "SERVERNAME")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	fs, err := session.Mount(context.Background(), "SHARENAME")
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
	dialer := &smb2.Dialer{
		Credentials: smb2.NTLMCredential{
			User:     "USERNAME",
			Password: "PASSWORD",
		},
	}

	session, err := dialer.Dial(context.Background(), "SERVERNAME")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	fs, err := session.Mount(context.Background(), "SHARENAME")
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

	fmt.Println(errors.Is(err, context.DeadlineExceeded)) // true
}
```

### Transparent DFS access ###

```go
import (
    "context"

    "github.com/hirochachacha/go-smb2/v2"
    "github.com/hirochachacha/go-smb2/v2/dfs"
)

func readFile(ctx context.Context, credentials smb2.Credentials) ([]byte, error) {
    client := dfs.New(&smb2.Dialer{Credentials: credentials})
    defer client.Close()
    return client.ReadFile(ctx, `\\server\share\folder\file.txt`)
}
```

Open returns a `*dfs.File` that wraps `*smb2.File` bound to the actual target
tree. `File.Name` and user-facing path errors use the original UNC, and the
embedded file serves I/O. `File.WithContext` remains available. The DFS
client has no Mount, Unmount, WithContext, io/fs adapter, RemoveAll, or MkdirAll.
The lower-level Share retains its io/fs adapter and recursive operations.

Server names in UNCs and referral targets are connection endpoints. Automatic
domain classification and domain-controller discovery are not provided. Symlink
targets may be relative or absolute UNCs; creating or reading a link does not
connect to its target. Rename across resolved shares is not supported.

Manual callers can use `errors.As` to inspect `*protocol.DFSReferralRequiredError`, then call
`Session.GetDFSReferrals(ctx, referral.Path)` and explicitly connect to a target.
`*protocol.CrossShareSymlinkError` supplies `ResolvedPath`, a complete continuation UNC with the
unparsed suffix already applied. GetDFSReferrals also accepts an empty DOMAIN
request or a domain-only DC request and returns name-list information directly.

### Low-level requests ###

`Share.Request()` returns an `x/protocol.Request`. The File API uses the same
implementation. Both `x/protocol` and `x/wire` have no compatibility guarantee;
their APIs may change or be removed. Protocol error types, including
`ResponseError`, are defined in `x/protocol`.

```go
response, err := share.Request().
    WithFileID(fileID).
    QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 24).
    Do(ctx)
if err != nil {
    return err
}
defer response.Close()
query, err := response.QueryInfo(0) // Validated response envelope.
if err != nil {
    return err
}
info, err := query.FileStandardInformation() // Validated payload for this request.
if err != nil {
    return err
}
size := info.EndOfFile()
```

Import packet types from `github.com/hirochachacha/go-smb2/v2/x/wire` and
request, response, and error types from
`github.com/hirochachacha/go-smb2/v2/x/protocol`. Protocol validates response
envelopes and READ/WRITE lengths before returning them. Typed accessors such
as `Response.QueryInfo` return protocol response wrappers. Their payload
accessors check the original request's information class or IOCTL code and
return validated wire decoders; getters need no additional `IsInvalid()`.
Directory accessors validate all entries before returning the list. Payload
validation occurs when an accessor is called, not merely when `Do` succeeds.
Unknown payloads remain available through `RawOutput()`. Converting raw bytes
from `RawOutput()`, `Response.Data()`, or `Bytes()` to a decoder requires
`IsInvalid()`. RPC and DFS payload interpretation remains with their callers.
All response views are read-only and remain valid until `Close()`. Direct READ
payloads are available through `DirectData()`; `Read()` requires a contiguous
response and returns an error for direct reception.

`Do(ctx)` sends and receives in one call. For pipelining, use `Send(ctx)` and
call `Receive()` exactly once, including after cancellation. Do not modify the
Request, its packets, or borrowed buffers until reception finishes. Sending
does not clone the Request. Symlink retries copy only their modified request;
`Response.ResolvedPath()` reports the path used by a leading CREATE.

`protocol.Dialer.Dial(ctx, initiator, transport)` negotiates and authenticates
an SMB session on an already connected Transport. Pass a fresh authentication
initiator for each session.

Packets in one Request form a related compound: later operations inherit the
preceding operation’s file handle, or the handle generated by its CREATE.
Use separate requests to operate on independent existing handles.

Response bytes are valid until `Response.Close()`; copy bytes you need to keep.
Closing a response releases its buffers, not server file handles. On failure,
the library reclaims handles created by that request's successful CREATEs that
have not already been closed. Existing handles are never automatically closed.
On success, the caller owns any handles left open by the request.

Low-level requests do not follow symbolic links by default. Enable
`WithFollowSymlinks(true)` on a request to follow them; ordinary File operations
retain their existing behavior.

### Custom transport settings ###

By default, `Dialer.Dial` connects to Direct TCP on port 445 using `TCPDialer{}`.
You can configure a custom port or supply a `net.Dialer` with custom dial
timeouts, keep-alive periods, or local address bindings:

```go
dialer := &smb2.Dialer{
	Credentials: smb2.NTLMCredential{
		User:     "USERNAME",
		Password: "PASSWORD",
	},
	TransportDialer: smb2.TCPDialer{
		Port: 8445,
		Dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	},
}
```

To connect using SMB over QUIC (UDP port 443 by default), configure
`QUICDialer`. It uses the `smb` ALPN and requires SMB 3.1.1. A nil TLS
configuration uses the system trust roots. Supply a CA pool when the server
certificate is not trusted by the system:

```go
dialer := &smb2.Dialer{
	Credentials: smb2.NTLMCredential{
		User:     "USERNAME",
		Password: "PASSWORD",
	},
	TransportDialer: smb2.QUICDialer{
		TLSConfig: &tls.Config{
			RootCAs: roots,
		},
	},
}
```

### Kerberos authentication ###

`KerberosCredential` uses [go-krb5/krb5](https://github.com/go-krb5/krb5)
with AES mutual authentication. Supply an authenticated Kerberos client;
`KerberosCredential` derives the registered `cifs/<server FQDN>` SPN from the
server name passed to `Dial`:

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

    dialer := &smb2.Dialer{
        Credentials:           smb2.KerberosCredential{Client: kcl},
        RequireMessageSigning: true,
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    session, err := dialer.Dial(ctx, "server.example.com")
    if err != nil {
        panic(err)
    }
    defer session.Close()
    share, err := session.Mount(ctx, "share")
    if err != nil {
        panic(err)
    }
    defer share.Unmount(ctx)
}
```

You can also supply a client created with `client.NewWithKeytab` (call
`Login` first) or `client.NewFromCCache`. Credential loading, renewal and
client cleanup belong to the caller. KDC exchanges use the Kerberos client's
timeouts; its ticket API does not accept the `Dialer.Dial` context.

Integration Testing
-------------------

The repository provides automated integration tests against Samba and Active Directory environments.

### Local Integration Suite (Docker Compose) ###

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
rejection of cross-target renames, concurrent first referrals, and invalidation
of open files when their DFS client closes.
The three-hop chain checks cold and cached reads, large files, and renames
through a different link to the same final share. The cycle test verifies
that resolution fails promptly and the connection remains usable. Resolution
also has a shared limit of 32 DFS and symlink traversal steps per operation.

### Custom Test Environments ###

#### DFS Testing ####

To run DFS tests against an existing environment (e.g. local Samba VM):

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

#### Kerberos Testing ####

To test against an external Kerberos environment, set `SMB2_KRB5_CONFIG` (krb5.conf
path), `SMB2_KRB5_USER`, `SMB2_KRB5_REALM`, `SMB2_KRB5_PASSWORD`,
`SMB2_KRB5_ADDR` (host:port), `SMB2_KRB5_SPN`, `SMB2_KRB5_SHARE`, and
`SMB2_KRB5_ENCRYPTED_SHARE`, then run:

```sh
go test -race -run '^TestKerberosIntegration$' -v .
```

#### SMB over QUIC Testing ####

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
