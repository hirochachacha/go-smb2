package smb2

// This file collects client-side policy defaults, traversal bounds, buffer sizes,
// and timeouts.
//
// These values are client implementation choices rather than protocol mandates.
// They reflect internal operational assumptions that may be adjusted over time,
// and any of these constants can be promoted to user-configurable settings
// in Dialer when exposing them proves practically useful.

import (
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

// client

const (
	// SMB 3.x clients advertise DFS support in NEGOTIATE ([MS-SMB2] 2.2.3).
	clientCapabilities = smb2.SMB2_GLOBAL_CAP_DFS | smb2.SMB2_GLOBAL_CAP_LARGE_MTU | smb2.SMB2_GLOBAL_CAP_ENCRYPTION
)

// client negotiation preferences
//
// Slices below are ordered by client preference (most preferred / strongest first).
// For ciphers, 256-bit algorithms precede 128-bit algorithms, and GCM modes precede CCM.
// For dialects, higher revisions precede lower ones ([MS-SMB2] 3.2.4.2.2).

var (
	clientHashAlgorithms        = []uint16{smb2.SHA512}
	clientCiphers               = []Cipher{AES256GCM, AES256CCM, AES128GCM, AES128CCM}
	clientCompressionAlgorithms = []uint16{smb2.SMB2_COMPRESSION_ALGORITHM_LZ4}
	clientDialects              = []Dialect{SMB311, SMB302, SMB300, SMB210, SMB202}
)

// client timeouts

const (
	clientCreditTimeout       = 30 * time.Second
	clientWriteTimeout        = 30 * time.Second
	clientPacketReadTimeout   = 30 * time.Second
	clientSessionCloseTimeout = 5 * time.Second
	clientQUICKeepAlivePeriod = 15 * time.Second
)

// client concurrency & pipeline limits

const (
	clientMaxCreditBalance = 128
	clientIOPipelineDepth  = 4
)

// client path resolution & traversal & receiver limits

const (
	clientMaxSymlinkDepth      = 8
	clientMaxGlobDepth         = 10000
	clientMaxShareResponseSize = 1024 * 1024
)

// client buffer/chunk size

const (
	clientMinBufSize       = 1024
	clientMaxCopyChunkSize = 1024 * 1024
	clientMaxCopyTotalSize = 16 * 1024 * 1024
)

// client DFS referral probing

// clientReferralInitialOutputSize is the first IOCTL output size requested for
// a DFS referral. STATUS_BUFFER_OVERFLOW doubles it up to
// maxDFSReferralResponseSize.
const clientReferralInitialOutputSize = 4096
