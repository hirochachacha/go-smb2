package ntlm

import (
	"bytes"
	"errors"

	"github.com/hirochachacha/go-smb2/internal/utf16le"
)

type ChallengeMessage struct {
	raw        []byte
	flags      uint32
	info       *targetInfoEncoder
	targetName []byte
}

// Unmarshal parses the ChallengeMessage in cmsg and returns the result.
func UnmarshalChallengeMessage(cmsg, nmsg []byte, targetSPN string) (*ChallengeMessage, error) {
	//        ChallengeMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-20: TargetNameFields
	// 20-24: NegotiateFlags
	// 24-32: ServerChallenge
	// 32-40: _
	// 40-48: TargetInfoFields
	// 48-56: Version
	//   56-: Payload
	if len(cmsg) < 48 {
		return nil, errors.New("message length is too short")
	}

	if !bytes.Equal(cmsg[:8], signature) {
		return nil, errors.New("invalid signature")
	}

	if le.Uint32(cmsg[8:12]) != NtLmChallenge {
		return nil, errors.New("invalid message type")
	}

	flags := le.Uint32(nmsg[12:16]) & le.Uint32(cmsg[20:24])

	if flags&NTLMSSP_REQUEST_TARGET == 0 {
		return nil, errors.New("invalid negotiate flags")
	}

	targetNameLen := le.Uint16(cmsg[12:14])    // cmsg.TargetNameLen
	targetNameMaxLen := le.Uint16(cmsg[14:16]) // cmsg.TargetNameMaxLen
	if targetNameMaxLen < targetNameLen {
		return nil, errors.New("invalid target name format")
	}
	targetNameBufferOffset := le.Uint32(cmsg[16:20]) // cmsg.TargetNameBufferOffset
	if len(cmsg) < int(targetNameBufferOffset+uint32(targetNameLen)) {
		return nil, errors.New("invalid target name format")
	}
	targetName := cmsg[targetNameBufferOffset : targetNameBufferOffset+uint32(targetNameLen)] // cmsg.TargetName

	if flags&NTLMSSP_NEGOTIATE_TARGET_INFO == 0 {
		return nil, errors.New("invalid negotiate flags")
	}

	targetInfoLen := le.Uint16(cmsg[40:42])    // cmsg.TargetInfoLen
	targetInfoMaxLen := le.Uint16(cmsg[42:44]) // cmsg.TargetInfoMaxLen
	if targetInfoMaxLen < targetInfoLen {
		return nil, errors.New("invalid target info format")
	}
	targetInfoBufferOffset := le.Uint32(cmsg[44:48]) // cmsg.TargetInfoBufferOffset
	if len(cmsg) < int(targetInfoBufferOffset+uint32(targetInfoLen)) {
		return nil, errors.New("invalid target info format")
	}
	targetInfo := cmsg[targetInfoBufferOffset : targetInfoBufferOffset+uint32(targetInfoLen)] // cmsg.TargetInfo
	info := newTargetInfoEncoder(targetInfo, utf16le.EncodeStringToBytes(targetSPN))
	if info == nil {
		return nil, errors.New("invalid target info format")
	}

	return &ChallengeMessage{
		raw:        cmsg,
		flags:      flags,
		info:       info,
		targetName: targetName,
	}, nil
}
