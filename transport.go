package smb2

import (
	"net"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"
)

// Transport is a built-in SMB transport. Close is idempotent and unblocks I/O.
type Transport interface{ protocol.Transport }

// NewTransport applies SMB Direct TCP framing to conn.
func NewTransport(conn net.Conn) Transport { return protocol.NewTransport(conn) }
