package smb2

import "github.com/hirochachacha/go-smb2/v2/x/protocol"

// Request starts a low-level request on this share. Symbolic links are not
// followed unless WithFollowSymlinks is enabled. This API has no compatibility
// guarantee and may change or be removed.
func (fs *Share) Request() *protocol.Request {
	if fs == nil {
		return (*protocol.Tree)(nil).Request()
	}
	return fs.treeConn.Request()
}
