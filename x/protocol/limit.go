package protocol

// Payload limits shared by the client, connection and credit sizing paths.
const (
	maxDirectTCPSize = 0xffffff // 16777215

	winMaxPayloadSize          = 1024 * 1024 // windows system don't accept more than 1M bytes request even though they tell us maxTransactSize etc > 1M
	maxSingleCreditPayloadSize = 64 * 1024
)
