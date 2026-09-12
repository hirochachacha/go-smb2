package smb2

// Payload limits shared by the client, connection and credit sizing paths.
const (
	winMaxPayloadSize          = 1024 * 1024 // windows system don't accept more than 1M bytes request even though they tell us maxXXXSize > 1M
	maxSingleCreditPayloadSize = 64 * 1024
	maxReparseDataBufferSize   = 16 * 1024
)
