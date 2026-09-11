package smb2

import "fmt"

type Command uint16

func (c Command) String() string {
	switch c {
	case SMB2_NEGOTIATE:
		return "SMB2_NEGOTIATE"
	case SMB2_SESSION_SETUP:
		return "SMB2_SESSION_SETUP"
	case SMB2_LOGOFF:
		return "SMB2_LOGOFF"
	case SMB2_TREE_CONNECT:
		return "SMB2_TREE_CONNECT"
	case SMB2_TREE_DISCONNECT:
		return "SMB2_TREE_DISCONNECT"
	case SMB2_CREATE:
		return "SMB2_CREATE"
	case SMB2_CLOSE:
		return "SMB2_CLOSE"
	case SMB2_FLUSH:
		return "SMB2_FLUSH"
	case SMB2_READ:
		return "SMB2_READ"
	case SMB2_WRITE:
		return "SMB2_WRITE"
	case SMB2_LOCK:
		return "SMB2_LOCK"
	case SMB2_IOCTL:
		return "SMB2_IOCTL"
	case SMB2_CANCEL:
		return "SMB2_CANCEL"
	case SMB2_ECHO:
		return "SMB2_ECHO"
	case SMB2_QUERY_DIRECTORY:
		return "SMB2_QUERY_DIRECTORY"
	case SMB2_CHANGE_NOTIFY:
		return "SMB2_CHANGE_NOTIFY"
	case SMB2_QUERY_INFO:
		return "SMB2_QUERY_INFO"
	case SMB2_SET_INFO:
		return "SMB2_SET_INFO"
	case SMB2_OPLOCK_BREAK:
		return "SMB2_OPLOCK_BREAK"
	default:
		return fmt.Sprintf("0x%04x", uint16(c))
	}
}

func (c Command) IsInvalid(data []byte) bool {
	switch c {
	case SMB2_NEGOTIATE:
		return NegotiateResponseDecoder(data).IsInvalid()
	case SMB2_SESSION_SETUP:
		return SessionSetupResponseDecoder(data).IsInvalid()
	case SMB2_LOGOFF:
		return LogoffResponseDecoder(data).IsInvalid()
	case SMB2_TREE_CONNECT:
		return TreeConnectResponseDecoder(data).IsInvalid()
	case SMB2_TREE_DISCONNECT:
		return TreeDisconnectResponseDecoder(data).IsInvalid()
	case SMB2_CREATE:
		return CreateResponseDecoder(data).IsInvalid()
	case SMB2_CLOSE:
		return CloseResponseDecoder(data).IsInvalid()
	case SMB2_FLUSH:
		return FlushResponseDecoder(data).IsInvalid()
	case SMB2_READ:
		return ReadResponseDecoder(data).IsInvalid()
	case SMB2_WRITE:
		return WriteResponseDecoder(data).IsInvalid()
	case SMB2_LOCK:
		return LockResponseDecoder(data).IsInvalid()
	case SMB2_QUERY_DIRECTORY:
		return QueryDirectoryResponseDecoder(data).IsInvalid()
	case SMB2_QUERY_INFO:
		return QueryInfoResponseDecoder(data).IsInvalid()
	case SMB2_SET_INFO:
		return SetInfoResponseDecoder(data).IsInvalid()
	case SMB2_IOCTL:
		return IoctlResponseDecoder(data).IsInvalid()
	case SMB2_ECHO:
		return EchoResponseDecoder(data).IsInvalid()
	case SMB2_CHANGE_NOTIFY:
		return ChangeNotifyResponseDecoder(data).IsInvalid()
	default:
		return true
	}
}
