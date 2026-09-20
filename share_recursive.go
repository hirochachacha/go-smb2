// Original: src/os/path.go and src/os/removeall_noat.go
//
// Copyright 2009 The Go Authors. All rights reserved.
// Portions Copyright 2016 Hiroshi Ioka. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package smb2

import (
	"context"
	"errors"
	"io"
	"os"
	"syscall"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// MkdirAll mimics os.MkdirAll
func (fs *Share) MkdirAll(ctx context.Context, path string, perm os.FileMode) error {
	var err error
	path, err = pathpkg.NormalizeRelPath(path)
	if err != nil {
		return err
	}

	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := fs.Stat(ctx, path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(path)
	for i > 0 && pathpkg.IsSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !pathpkg.IsSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent
		err = fs.MkdirAll(ctx, path[0:j-1], perm)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = fs.Mkdir(ctx, path, perm)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := fs.Lstat(ctx, path)
		if err1 == nil && dir.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

// RemoveAll removes path and any children it contains.
// It removes everything it can but returns the first error
// it encounters. If the path does not exist, RemoveAll
// returns nil (no error). Symbolic links in parent path components are
// followed, but links at path or within its subtree are removed themselves.
func (fs *Share) RemoveAll(ctx context.Context, path string) error {
	// An empty path is a no-op, matching os.RemoveAll. A path that only
	// normalizes to empty (".", ".\") names the share root per
	// [MS-SMB2] 2.2.13 and is rejected instead of deleting the root.
	if len(path) == 0 {
		return nil
	}

	var err error
	path, err = pathpkg.NormalizeRelPath(path)
	if err != nil {
		return err
	}
	if len(path) == 0 {
		return os.ErrInvalid
	}

	// Simple case: if direct remove works, we're done.
	err = fs.Remove(ctx, path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// SMB CREATE returns attributes as well as a handle, so combine the
	// upstream Lstat and Open without a separate metadata round trip.
	fd, serr := fs.openDirForRemove(ctx, path)
	if serr != nil {
		if errors.Is(serr, os.ErrNotExist) || errors.Is(serr, erref.STATUS_NOT_A_DIRECTORY) {
			return nil
		}
		if errors.Is(serr, syscall.ENOTDIR) || errors.Is(serr, syscall.ELOOP) {
			return err
		}
		return serr
	}
	path = fd.name

	// Remove contents & return first error, following os/removeall_noat.go.
	err = nil
	for {
		const reqSize = 1024
		var names []string
		var readErr error
		for {
			numErr := 0
			names, readErr = fd.Readdirnames(ctx, reqSize)
			for _, name := range names {
				err1 := fs.RemoveAll(ctx, pathpkg.Join(path, name))
				if err == nil {
					err = err1
				}
				if err1 != nil {
					numErr++
				}
			}
			if numErr != reqSize {
				break
			}
		}

		// Deletion can reshuffle directory entries. Reopen after a batch
		// rather than continuing from a cursor that could skip entries.
		fd.Close(ctx)
		if readErr == io.EOF {
			break
		}
		if err == nil {
			err = readErr
		}
		if len(names) == 0 {
			break
		}
		if len(names) < reqSize {
			err1 := fs.Remove(ctx, path)
			if err1 == nil || errors.Is(err1, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
		}

		fd, serr = fs.openDirForRemove(ctx, path)
		if serr != nil {
			if errors.Is(serr, os.ErrNotExist) {
				return nil
			}
			return serr
		}
		path = fd.name
	}

	// Remove already retries read-only targets, regardless of the client OS.
	err1 := fs.Remove(ctx, path)
	if err1 == nil || errors.Is(err1, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		err = err1
	}
	return err
}

func (fs *Share) openDirForRemove(ctx context.Context, name string) (*File, error) {
	if !pathpkg.ValidRelPath(name) {
		return nil, os.ErrInvalid
	}

	// Resolve parent links and open the final component itself. Create uses
	// read/write sharing without delete sharing, keeping the directory pinned.
	res, err := fs.Request().WithFollowSymlinks(true).
		Create(name, wire.FILE_LIST_DIRECTORY|wire.FILE_READ_ATTRIBUTES|wire.READ_CONTROL|wire.SYNCHRONIZE,
			wire.FILE_OPEN, wire.FILE_OPEN_REPARSE_POINT, wire.FILE_ATTRIBUTE_NORMAL).
		Do(ctx)
	if err != nil {
		if errors.Is(err, erref.STATUS_STOPPED_ON_SYMLINK) {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ELOOP}
		}
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	defer res.Close()

	r, err := res.Create(0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	if r.FileAttributes()&wire.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = fs.closeFile(context.Background(), r.FileId().Decode())
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ELOOP}
	}
	if r.FileAttributes()&wire.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = fs.closeFile(context.Background(), r.FileId().Decode())
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOTDIR}
	}

	f := fs.newFile(r, res.ResolvedPath())
	return f, nil
}
