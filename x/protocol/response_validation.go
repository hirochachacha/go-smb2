package protocol

import (
	"fmt"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// acceptRequest applies the command-specific response validation which needs
// information from the original request (currently the requested I/O length).
func acceptRequest(rr *outstandingRequest, rp *recvPacket, dialect uint16) (*recvPacket, error) {
	if rr == nil {
		if rp != nil {
			rp.close()
		}
		return nil, &InternalError{"nil outstanding request"}
	}
	accepted, err := acceptWithLimits(rr.cmd, rp, dialect, rr.expectedRead, rr.hasExpectedRead, rr.expectedWrite, rr.hasExpectedWrite)
	if err == nil {
		accepted.payloadRequest = rr.payloadRequest
	}
	return accepted, err
}

func validateResponseBody(cmd wire.Command, body []byte, dialect uint16, expectedRead uint32, hasRead bool, expectedWrite uint32, hasWrite bool) error {
	invalid := func() error {
		name := cmd.String()
		switch cmd {
		case wire.SMB2_SESSION_SETUP:
			name = "session setup"
		}
		return &InvalidResponseError{fmt.Sprintf("broken %s response format", name)}
	}
	switch cmd {
	case wire.SMB2_CREATE:
		if wire.CreateResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_CLOSE:
		if wire.CloseResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_FLUSH:
		if wire.FlushResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_READ:
		r := wire.ReadResponseDecoder(body)
		if r.IsInvalid() {
			return invalid()
		}
		if hasInvalidReadFlags(r, dialect) {
			return invalid()
		}
		if hasRead && r.DataLength() > expectedRead {
			return &InvalidResponseError{"read length exceeds requested length"}
		}
	case wire.SMB2_WRITE:
		r := wire.WriteResponseDecoder(body)
		if r.IsInvalid() {
			return invalid()
		}
		if hasWrite && r.Count() > expectedWrite {
			return &InvalidResponseError{"write count exceeds requested length"}
		}
	case wire.SMB2_LOCK:
		if wire.LockResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_IOCTL:
		if wire.IoctlResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_QUERY_DIRECTORY:
		if wire.QueryDirectoryResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_CHANGE_NOTIFY:
		if wire.ChangeNotifyResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_QUERY_INFO:
		if wire.QueryInfoResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_SET_INFO:
		if wire.SetInfoResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_TREE_CONNECT:
		if wire.TreeConnectResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_TREE_DISCONNECT:
		if wire.TreeDisconnectResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_ECHO:
		if wire.EchoResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_LOGOFF:
		if wire.LogoffResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	case wire.SMB2_SESSION_SETUP:
		if wire.SessionSetupResponseDecoder(body).IsInvalid() {
			return invalid()
		}
	}
	return nil
}

func validateResponsePacket(cmd wire.Command, rp *recvPacket, dialect uint16, expectedRead uint32, hasRead bool, expectedWrite uint32, hasWrite bool) error {
	if cmd == wire.SMB2_READ && rp != nil && len(rp.ext) != 0 {
		r := wire.ReadResponseDecoder(rp.codec().Body())
		if r.IsInvalidHeader() || len(rp.ext) != int(r.DataLength()) || hasInvalidReadFlags(r, dialect) {
			return &InvalidResponseError{"broken read response format"}
		}
		if hasRead && r.DataLength() > expectedRead {
			return &InvalidResponseError{"read length exceeds requested length"}
		}
		return nil
	}
	return validateResponseBody(cmd, rp.codec().Body(), dialect, expectedRead, hasRead, expectedWrite, hasWrite)
}
