package smb2

import (
	. "github.com/hirochachacha/go-smb2/internal/smb2"
)

const (
	clientCapabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms = []uint16{SHA512}
	clientCiphers        = []uint16{AES128CCM, AES128GCM}
	clientDialects       = []uint16{SMB202, SMB210, SMB300, SMB302, SMB311}
)

const (
	clientMaxCreditBalance = 128
)
