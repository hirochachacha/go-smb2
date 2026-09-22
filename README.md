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
- **Go Integration**: `io/fs` interface support and `context.Context` support.

Installation
------------

Requires Go 1.27 or later.

`go get github.com/hirochachacha/go-smb2/v2`

Documentation
-------------

<http://godoc.org/github.com/hirochachacha/go-smb2/v2>

Examples
--------

A `smb2.Dialer` creates an independent `Session` for each `Dial` call. Mount a
share by name; its operations take share-relative paths. `Share.Unmount`
disconnects that tree, while `Session.Close` closes the connection and invalidates
all its Shares and Files. The Dialer owns no connections and needs no Close.
Do not modify its configuration while it is in use, including by a DFS client.

For transparent DFS and cross-server symbolic links, use `client.New(dialer)`.
Its path operations take absolute UNCs and it owns and reuses Sessions and Shares
until `Client.Close`, including sessions used only to retrieve referrals. Close
cancels connection establishment and invalidates open Files. Custom credential
and transport factories must cooperate with context cancellation.

Cancellation does not always return control immediately. Kerberos KDC exchanges
use the authentication dependency's timeouts and cannot be interrupted by a
context. CREATE and LOCK requests may wait for the server's final response so
that handles and locks can be cleaned up safely.

Atomic append across independently opened file handles, sessions, or clients
is not guaranteed. Applications must coordinate multiple writers to the same
file; the library does not implicitly acquire SMB locks for append operations.
As with `os.File`, the behavior of `Seek` on an `O_APPEND` file is unspecified.
Append opens require ordinary write permission, rather than append-only access.
Copies into append-opened files use client-side reads and writes.

### File manipulation ###

```go
package main

import (
 "context"
 "fmt"
 "io"

 "github.com/hirochachacha/go-smb2/v2"
 "github.com/hirochachacha/go-smb2/v2/auth"
)

func main() {
 dialer := &smb2.Dialer{
  Credentials: auth.NTLMCredential{
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
 "github.com/hirochachacha/go-smb2/v2/auth"
)

func main() {
 dialer := &smb2.Dialer{
  Credentials: auth.NTLMCredential{
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
 "github.com/hirochachacha/go-smb2/v2/auth"
)

func main() {
 dialer := &smb2.Dialer{
  Credentials: auth.NTLMCredential{
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
```

### Transparent DFS access ###

```go
import (
    "context"

    "github.com/hirochachacha/go-smb2/v2"
    "github.com/hirochachacha/go-smb2/v2/client"
)

c := client.New(&smb2.Dialer{Credentials: credentials})
defer c.Close()

data, err := c.ReadFile(ctx, `\\server\share\folder\file.txt`)
if err != nil {
  panic(err)
}

fmt.Println(string(data))
```

Open returns a `*client.File` that wraps `*smb2.File` bound to the actual target
tree. `File.Name` and user-facing path errors use the original UNC, and the
embedded file serves I/O. `File.WithContext` remains available. The client
also supports `MkdirAll` and `RemoveAll`. Use `io/fs.Glob` with
`WithContext` for glob matching.

`Client.WithContext` exposes an `io/fs` filesystem with `server/share/path`
names. Its virtual root lists currently cached servers, not all servers on
the network. Server directories list shares; uncached servers can also be
accessed directly. For example, using the standard `io/fs` package:

```go
network := c.WithContext(ctx)
project, err := fs.Sub(network, "server/share/project")
if err != nil {
    panic(err)
}
data, err := fs.ReadFile(project, "config.json")
```

Server names in UNCs and referral targets are connection endpoints. Automatic
domain classification and domain-controller discovery are not provided. Symlink
targets may be relative or absolute UNCs; creating or reading a link does not
connect to its target. Rename across resolved shares is not supported.

Manual callers can use `errors.As` to inspect `*protocol.DFSReferralRequiredError`, then call
`Session.GetDFSReferrals(ctx, referral.Path, nil)` and explicitly connect to a target.
`*protocol.CrossShareSymlinkError` supplies `ResolvedPath`, a complete continuation UNC with the
unparsed suffix already applied. GetDFSReferrals also accepts an empty DOMAIN
request or a domain-only DC request and returns name-list information directly.
Pass `&dfs.ReferralOptions{SiteName: "SiteA"}` instead of `nil` for site-aware
referral ordering.

### Low-level requests ###

The low-level API lets you work directly with the SMB2 protocol.
The APIs in `x/protocol` and `x/wire` are experimental and have no stability
guarantee; they may change without backward compatibility.

```go
response, err := share.Request().
    WithFileID(fileID).
    QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 24).
    Do(ctx)
if err != nil {
    return err
}
defer response.Close()
query, err := response.QueryInfo(0)
if err != nil {
    return err
}
info, err := query.FileStandardInformation()
if err != nil {
    return err
}
size := info.EndOfFile()
```

### Custom transport settings ###

By default, `Dialer.Dial` connects to Direct TCP on port 445 using `TCPDialer{}`.
You can configure a custom port or supply a `net.Dialer` with custom dial
timeouts, keep-alive periods, or local address bindings:

```go
dialer := &smb2.Dialer{
 Credentials: auth.NTLMCredential{
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
 Credentials: auth.NTLMCredential{
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

`auth.NewKerberosCredential` loads credentials and performs Kerberos login
with AES mutual authentication. No external client object is needed;
`auth.KerberosCredential` derives the registered `cifs/<server FQDN>` SPN from the
server name passed to `Dial`:

```go
package main

import (
    "context"
    "os"
    "time"

    "github.com/hirochachacha/go-smb2/v2"
    "github.com/hirochachacha/go-smb2/v2/auth"
)

func main() {
    creds, err := auth.NewKerberosCredential(auth.KerberosOptions{
        User:       "USERNAME",
        Realm:      "EXAMPLE.COM",
        Password:   os.Getenv("KRB5_PASSWORD"),
        ConfigFile: "/etc/krb5.conf",
    })
    if err != nil {
        panic(err)
    }
    defer creds.Close()

    dialer := &smb2.Dialer{
        Credentials:           creds,
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

Use `KeytabFile` instead of `Password` for keytab authentication. For an
existing file credential cache, use `CCacheFile` without `User`, `Realm`, or
`Password`; its tickets retain their existing lifetime. `ConfigFile` is
required. The credential owns its cache and password/keytab ticket renewal;
call `Close` after all uses. Each authentication gets a fresh initiator.
KDC exchanges use internal timeouts and cannot be canceled by the
`Dialer.Dial` context.

Integration Testing
-------------------

```jsonc
// client_conf.json — place in the repository root for integration tests.
// Remove comments before saving: the loader accepts standard JSON only.
[
  {
    "name": "samba-ntlm",
    "max_credit_balance": 128,
    "transport": {
      "type": "tcp",
      "host": "localhost",
      "port": 445
    },
    "conn": {
      "signing": true // Require message signing.
      // ,"dialect": 785 // Optional: 528 = SMB 2.1, 770 = 3.0.2, 785 = 3.1.1.
                        // Omit to negotiate automatically.
      // ,"guid": "" // Currently unused by the test loader.
    },
    "session": {
      "type": "ntlm",
      "user": "USERNAME",
      "passwd": "PASSWORD",
      "domain": "WORKGROUP"
      // ,"workstation": "CLIENT"
      // ,"targetSPN": "cifs/server.example.com"
    },
    "tree_conn": {
      "share1": "writable",
      "share2": "readonly"
    }
  },
  {
    "name": "samba-kerberos",
    "transport": {
      "type": "tcp",
      "host": "server.example.com",
      "port": 445
    },
    "conn": {"signing": true},
    "session": {
      "type": "kerberos",
      "user": "USERNAME",
      "passwd": "PASSWORD",
      "realm": "EXAMPLE.COM",
      "krb5Config": "/etc/krb5.conf"
      // ,"targetSPN": "cifs/server.example.com"
    },
    "tree_conn": {
      "share1": "writable",
      "share2": "readonly"
    }
    // Uncomment to select the dedicated SMB 2.1 / 3.0.2 / 3.1.1 test
    // instead of ordinary file tests. share2 is then unused; share1 must
    // allow unencrypted access, and encrypted_share must require encryption.
    // ,"kerberos": {"encrypted_share": "encrypted"}
  },
  {
    "name": "samba-quic",
    "transport": {
      "type": "quic",
      "host": "server.example.com",
      "port": 443
      // Optional TLS settings; omitted values use the host and system roots.
      // ,"tls": {
      //   "server_name": "server.example.com",
      //   "ca_file": "/path/to/ca.pem" // PEM; relative paths use the working directory.
      // }
    },
    "conn": {"signing": true, "dialect": 785},
    "session": {
      "type": "ntlm", // Kerberos session settings also apply to QUIC.
      "user": "USERNAME",
      "passwd": "PASSWORD",
      "domain": "WORKGROUP"
    },
    "tree_conn": {"share1": "writable", "share2": "readonly"}
  },
  {
    "name": "samba-dfs", // Dedicated DFS test; excluded from ordinary file tests.
    "transport": {"type": "tcp", "host": "127.0.0.1", "port": 445},
    "session": {
      "type": "ntlm",
      "user": "USERNAME",
      "passwd": "PASSWORD",
      "domain": "WORKGROUP"
    },
    "tree_conn": {"share1": "dfs"}, // Namespace share; share2 is unused.
    "dfs": {
      // Distinct logical server names, all using the transport endpoint above.
      "target": "127.0.0.2",
      "second_target": "127.0.0.3",
      "link": "link"
      // Required namespace links:
      // link, link-alias -> 127.0.0.2 / dfs-target
      // link-extra       -> 127.0.0.3 / dfs-encrypted / nested
      // dfs-encrypted must require SMB encryption.
    }
  }
]
```
