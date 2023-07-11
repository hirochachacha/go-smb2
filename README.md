smb2
====

[![Build Status](https://github.com/hirochachacha/go-smb2/actions/workflows/go.yml/badge.svg)](https://github.com/hirochachacha/go-smb2/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/hirochachacha/go-smb2.svg)](https://pkg.go.dev/github.com/hirochachacha/go-smb2)

Description
-----------

SMB2/3 client implementation.

Installation
------------

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

	names, err := s.ListSharenames()
	if err != nil {
		panic(err)
	}

	for _, name := range names {
		fmt.Println(name)
	}
}
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


### Readdir example via DFS ###

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

	ipc, err := s.Mount("$IPC")
	if err != nil {
		panic(err)
	}
	defer ipc.Umount()


	// Fetch the DFS list for the directory, and specify if its DFS link
	targetList, err := ipc.GetDFSTargetList(s, "SHARENAME", "DFSDIR", false)
	if err != nil {
		panic(err)
	}

	isLink := false

	targetList, err := ipc.GetDFSTargetList(session, sharename, dfsdir, false)
	if err != nil {
		t.Error("unexpected error: ", err)
	}

	for _, target := range targetList {

		address := target.TargetAddress
		actualTargetFolder := target.TargetFolder

		//In case of non dfs links, what we get in Target folder is the base address of dfs folder. We need to append
		//the directory name to reach the actual target
		if len(target.TargetFolder) > 0 && !isLink {
			actualTargetFolder = fmt.Sprintf("%s//%s", target.TargetFolder, dirname)
		} else if !isLink {
			actualTargetFolder = dirname
		}
		CONNECT := fmt.Sprintf("%s:%d", address, 445)
		conn, err := net.Dial("tcp", CONNECT)
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

		sh, err := s.Mount(target.TargetShare)
		if err != nil {
			panic(err)
		}

		_, err = sh.ReadDir(actualTargetFolder)
		if err == nil {
			break
		}
	}
}

```
