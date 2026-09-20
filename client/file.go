package client

import (
	v2 "github.com/hirochachacha/go-smb2/v2"
)

// File is an open file on a resolved DFS target. The embedded smb2.File serves
// I/O against the tree that was actually opened; name keeps the original UNC
// supplied by the caller for Name to return.
type File struct {
	*v2.File
	name string
}

// Name returns the original UNC the file was opened with.
func (f *File) Name() string {
	if f == nil {
		return ""
	}
	return f.name
}
