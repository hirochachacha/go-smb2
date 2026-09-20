package protocol

// Payload limits shared by the client, connection and credit sizing paths.
const (
	maxDirectTCPSize = 0xffffff // 16777215
	// maxNetBTSize     = 0x1ffff  // 131071

	winMaxPayloadSize          = 1024 * 1024 // windows system don't accept more than 1M bytes request even though they tell us maxXXXSize > 1M
	maxSingleCreditPayloadSize = 64 * 1024
	maxReparseDataBufferSize   = 16 * 1024
	// [MS-DFSC] 3.3.5.2 caps a domain referral retry at 56 KB.
	maxDFSReferralResponseSize = 56 * 1024
)
