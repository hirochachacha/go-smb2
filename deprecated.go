package smb2

import (
	"context"
	"net"
)

type (
	Client           = Session  // deprecated type name
	RemoteFileSystem = Share    // deprecated type name
	RemoteFile       = File     // deprecated type name
	RemoteFileStat   = FileStat // deprecated type name
)

const MaxReadSizeLimit = 0x100000 // deprecated constant

// deprecated. use DialWithHostname instead. see https://github.com/hirochachacha/go-smb2/issues/40
func (d *Dialer) Dial(tcpConn net.Conn) (*Session, error) {
	return d.DialWithHostname(tcpConn, "")
}

// deprecated. use DialContextWithHostname instead. see https://github.com/hirochachacha/go-smb2/issues/40
func (d *Dialer) DialContext(ctx context.Context, tcpConn net.Conn) (*Session, error) {
	return d.DialContextWithHostname(ctx, tcpConn, "")
}
