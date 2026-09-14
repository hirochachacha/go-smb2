package smb2

import (
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

// client

const (
	// SMB 3.x clients advertise DFS support in NEGOTIATE ([MS-SMB2] 2.2.3).
	clientCapabilities = smb2.SMB2_GLOBAL_CAP_DFS | smb2.SMB2_GLOBAL_CAP_LARGE_MTU | smb2.SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms        = []uint16{smb2.SHA512}
	clientCiphers               = []uint16{smb2.AES128GCM, smb2.AES128CCM, smb2.AES256GCM, smb2.AES256CCM}
	clientCompressionAlgorithms = []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4}
	clientDialects              = []uint16{smb2.SMB311, smb2.SMB302, smb2.SMB300, smb2.SMB210, smb2.SMB202}
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth      = 8
	clientMaxShareResponseSize = 1024 * 1024
)
