// Original: src/os/path.go
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

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

// MkdirAll mimics os.MkdirAll
func (fs *Share) MkdirAll(ctx context.Context, path string, perm os.FileMode) error {
	path = normPath(path)

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
	for i > 0 && IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !IsPathSeparator(path[j-1]) { // Scan backward over element.
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
// returns nil (no error).
func (fs *Share) RemoveAll(ctx context.Context, path string) error {
	// An empty path is a no-op, matching os.RemoveAll. A path that only
	// normalizes to empty (".", ".\") names the share root per
	// [MS-SMB2] 2.2.13 and is rejected instead of deleting the root.
	if len(path) == 0 {
		return nil
	}

	original := path
	path = normPath(path)
	if len(path) == 0 {
		return &os.PathError{Op: "removeall", Path: original, Err: os.ErrInvalid}
	}

	// Simple case: if direct remove works, we're done.
	err := fs.removeDirect(ctx, path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}

	return fs.removeAllSubtree(ctx, path, err)
}

func (fs *Share) removeDirect(ctx context.Context, name string) error {
	// [MS-SMB2] 2.2.13 defines a zero-length CREATE file name as a request
	// to open the root of the share, so an empty name must not reach CREATE.
	if len(name) == 0 {
		return &os.PathError{Op: "remove", Path: name, Err: os.ErrInvalid}
	}

	if err := validatePath("remove", name, false); err != nil {
		return err
	}

	remove := fs.request().
		withoutSymlinks().
		create(name, smb2.DELETE, smb2.FILE_OPEN, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
		setInfo(smb2.SMB2_0_INFO_FILE, smb2.FileDispositionInformation, 0, &smb2.FileDispositionInformationEncoder{DeletePending: 1}).
		close()
	res, err := remove.sendRecv(ctx)
	if err != nil {
		if !errors.Is(err, erref.STATUS_ACCESS_DENIED) && !errors.Is(err, erref.STATUS_CANNOT_DELETE) {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}

		if err := fs.chmod(ctx, nil, name, 0o666, false); err != nil {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}

		remove := fs.request().
			withoutSymlinks().
			create(name, smb2.DELETE, smb2.FILE_OPEN, smb2.FILE_OPEN_REPARSE_POINT, smb2.FILE_ATTRIBUTE_NORMAL).
			setInfo(smb2.SMB2_0_INFO_FILE, smb2.FileDispositionInformation, 0, &smb2.FileDispositionInformationEncoder{DeletePending: 1}).
			close()
		res, err = remove.sendRecv(ctx)
		if err != nil {
			return &os.PathError{Op: "remove", Path: name, Err: err}
		}
	}
	res.close()
	return nil
}

func (fs *Share) openDirForRemove(ctx context.Context, name string) (*File, error) {
	if err := validatePath("open", name, false); err != nil {
		return nil, err
	}

	req := &smb2.CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: smb2.SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   smb2.Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        smb2.FILE_LIST_DIRECTORY | smb2.FILE_READ_ATTRIBUTES | smb2.READ_CONTROL | smb2.SYNCHRONIZE,
		FileAttributes:       smb2.FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          smb2.FILE_SHARE_READ | smb2.FILE_SHARE_WRITE, // Pin directory: no delete sharing
		CreateDisposition:    smb2.FILE_OPEN,
		CreateOptions:        smb2.FILE_DIRECTORY_FILE | smb2.FILE_OPEN_REPARSE_POINT,
		Name:                 name,
	}

	res, err := fs.sendRecv(ctx, req)
	if err != nil {
		if errors.Is(err, erref.STATUS_NOT_A_DIRECTORY) {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOTDIR}
		}
		if errors.Is(err, erref.STATUS_STOPPED_ON_SYMLINK) {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ELOOP}
		}
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	defer res.close()

	r := smb2.CreateResponseDecoder(res.data(0))
	if r.FileAttributes()&smb2.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ELOOP}
	}
	if r.FileAttributes()&smb2.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOTDIR}
	}

	f := fs.routed(res.treeConn).newFile(r, name)
	return f, nil
}

func (fs *Share) removeAllSubtree(ctx context.Context, path string, originalErr error) error {
	fd, err := fs.openDirForRemove(ctx, path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.ENOTDIR {
			// Not a directory; return original error from removeDirect.
			if originalErr != nil {
				return originalErr
			}
			return err
		}
		return err
	}

	// Remove contents while keeping the directory pinned.
	var firstErr error
	for {
		names, err1 := fd.Readdirnames(ctx, 100)
		for _, name := range names {
			childPath := path + string(PathSeparator) + name
			errChild := fs.removeDirect(ctx, childPath)
			if errChild != nil && !os.IsNotExist(errChild) {
				// If child is a directory, recurse into it.
				errChild = fs.removeAllSubtree(ctx, childPath, errChild)
			}
			if errChild != nil && !os.IsNotExist(errChild) && firstErr == nil {
				firstErr = errChild
			}
		}
		if err1 == io.EOF {
			break
		}
		if firstErr == nil && err1 != nil {
			firstErr = err1
		}
		if len(names) == 0 {
			break
		}
	}

	// Close directory before unlinking it.
	fd.Close(ctx)

	// Remove the now-empty directory itself.
	err = fs.removeDirect(ctx, path)
	if err == nil || os.IsNotExist(err) {
		return firstErr
	}
	if firstErr == nil {
		firstErr = err
	}
	return firstErr
}
