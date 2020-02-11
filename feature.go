package smb2

import (
	. "github.com/omnifocal/go-smb2/internal/smb2"
)

// client

const (
	clientCapabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms = []uint16{SHA512}
	clientCiphers        = []uint16{AES128GCM, AES128CCM}
	clientDialects       = []uint16{SMB311, SMB302, SMB300, SMB210, SMB202}
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth = 8
)

// server

const (
	serverCapabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_ENCRYPTION
)

var ( // ordered by priority
	serverHashAlgorithms = []uint16{SHA512}
	serverCiphers        = []uint16{AES128GCM, AES128CCM}
	serverDialects       = []uint16{SMB311, SMB302, SMB300, SMB210, SMB202}
)

const (
	serverMaxTransactSize = 8 * 1024 * 1024
	serverMaxReadSize     = 8 * 1024 * 1024
	serverMaxWriteSize    = 8 * 1024 * 1024
)
