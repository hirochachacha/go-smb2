package smb2

import (
	"testing"
)

func TestCommandString(t *testing.T) {
	tests := []struct {
		cmd      Command
		expected string
	}{
		{SMB2_NEGOTIATE, "SMB2_NEGOTIATE"},
		{SMB2_SESSION_SETUP, "SMB2_SESSION_SETUP"},
		{SMB2_LOGOFF, "SMB2_LOGOFF"},
		{SMB2_TREE_CONNECT, "SMB2_TREE_CONNECT"},
		{SMB2_TREE_DISCONNECT, "SMB2_TREE_DISCONNECT"},
		{SMB2_CREATE, "SMB2_CREATE"},
		{SMB2_CLOSE, "SMB2_CLOSE"},
		{SMB2_FLUSH, "SMB2_FLUSH"},
		{SMB2_READ, "SMB2_READ"},
		{SMB2_WRITE, "SMB2_WRITE"},
		{SMB2_LOCK, "SMB2_LOCK"},
		{SMB2_IOCTL, "SMB2_IOCTL"},
		{SMB2_CANCEL, "SMB2_CANCEL"},
		{SMB2_ECHO, "SMB2_ECHO"},
		{SMB2_QUERY_DIRECTORY, "SMB2_QUERY_DIRECTORY"},
		{SMB2_CHANGE_NOTIFY, "SMB2_CHANGE_NOTIFY"},
		{SMB2_QUERY_INFO, "SMB2_QUERY_INFO"},
		{SMB2_SET_INFO, "SMB2_SET_INFO"},
		{SMB2_OPLOCK_BREAK, "SMB2_OPLOCK_BREAK"},
		{Command(0xffff), "0xffff"},
	}

	for _, tt := range tests {
		if got := tt.cmd.String(); got != tt.expected {
			t.Errorf("Command(%d).String() = %q; want %q", tt.cmd, got, tt.expected)
		}
	}
}

func TestCommandIsInvalid(t *testing.T) {
	// Empty slice should be invalid for all commands
	var empty []byte
	cmds := []Command{
		SMB2_NEGOTIATE,
		SMB2_SESSION_SETUP,
		SMB2_LOGOFF,
		SMB2_TREE_CONNECT,
		SMB2_TREE_DISCONNECT,
		SMB2_CREATE,
		SMB2_CLOSE,
		SMB2_FLUSH,
		SMB2_READ,
		SMB2_WRITE,
		SMB2_IOCTL,
		SMB2_ECHO,
		SMB2_QUERY_DIRECTORY,
		SMB2_QUERY_INFO,
		SMB2_SET_INFO,
		Command(0xffff),
	}

	for _, cmd := range cmds {
		if !cmd.IsInvalid(empty) {
			t.Errorf("Command(%s).IsInvalid(empty) = false; want true", cmd)
		}
	}
}
