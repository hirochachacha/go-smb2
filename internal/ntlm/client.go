package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"strings"
	"time"
)

// NTLM v2 client
type Client struct {
	User        string
	Password    string
	Domain      string // e.g "WORKGROUP", "MicrosoftAccount"
	Workstation string // e.g "localhost", "HOME-PC"

	TargetSPN       string           // SPN ::= "service/hostname[:port]"; e.g "cifs/remotehost:1020"
	channelBindings *channelBindings // reserved for future implementation

	state int // 0: initial, 1: negotiated, 2: authenticated

	negotiateFlags uint32

	exportedSessionKey []byte
	clientSigningKey   []byte
	serverSigningKey   []byte

	clientHandle *rc4.Cipher
	serverHandle *rc4.Cipher
}

func (c *Client) Negotiate() ([]byte, error) {
	if c.state != 0 {
		panic("bad state")
	}

	//        NegotiateMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-16: NegotiateFlags
	// 16-24: DomainNameFields
	// 24-32: WorkstationFields
	// 32-40: Version
	//   40-: Payload

	off := 32

	if useVersion {
		off += 8
	}

	nmsg := make([]byte, off)

	copy(nmsg[:8], signature)
	le.PutUint32(nmsg[8:12], NtLmNegotiate)
	le.PutUint32(nmsg[12:16], clientDefaultFlags)

	if useVersion {
		copy(nmsg[32:], version)
	}

	c.state = 1

	return nmsg, nil
}

func (c *Client) Authenticate(nmsg, cmsg []byte) ([]byte, error) {
	if c.state != 1 && c.state != 0 {
		panic("bad state")
	}

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

	if string(cmsg[:8]) != signature {
		return nil, errors.New("invalid signature")
	}

	if le.Uint32(cmsg[8:12]) != NtLmChallenge {
		return nil, errors.New("invalid message type")
	}

	c.negotiateFlags = le.Uint32(nmsg[12:16]) & le.Uint32(cmsg[20:24])

	targetInfoLen := le.Uint16(cmsg[40:42])                                                   // cmsg.TargetInfoLen
	targetInfoBufferOffset := le.Uint32(cmsg[44:48])                                          // cmsg.TargetInfoBufferOffset
	targetInfo := cmsg[targetInfoBufferOffset : targetInfoBufferOffset+uint32(targetInfoLen)] // cmsg.TargetInfo
	info := newTargetInfoEncoder(targetInfo, c.encodeString(c.TargetSPN))
	if info == nil {
		return nil, errors.New("invalid target info format")
	}

	//        AuthenticateMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-20: LmChallengeResponseFields
	// 20-28: NtChallengeResponseFields
	// 28-36: DomainNameFields
	// 36-44: UserNameFields
	// 44-52: WorkstationFields
	// 52-60: EncryptedRandomSessionKeyFields
	// 60-64: NegotiateFlags
	// 64-72: Version
	// 72-88: MIC
	//   88-: Payload

	off := 64

	if useVersion {
		off += 8
	}

	if useMIC {
		off += 16
	}

	domain := c.encodeString(c.Domain)
	user := c.encodeString(c.User)
	workstation := c.encodeString(c.Workstation)

	// LmChallengeResponseLen = 24
	// NtChallengeResponseLen =
	//   len(Response) = 16
	//	 len(NTLMv2ClientChallenge) =
	//     min len size = 28
	//     target info size
	//     padding = 4
	// len(EncryptedRandomSessionKey) = 0 or 16

	amsg := make([]byte, off+len(domain)+len(user)+len(workstation)+
		24+
		(16+(28+info.size()+4))+
		16)

	copy(amsg[:8], signature)
	le.PutUint32(amsg[8:12], NtLmAuthenticate)

	if domain != nil {
		le.PutUint16(amsg[28:30], uint16(len(domain)))
		le.PutUint16(amsg[30:32], uint16(len(domain)))
		le.PutUint32(amsg[32:36], uint32(off))
		off += copy(amsg[off:], domain)
	}

	if user != nil {
		le.PutUint16(amsg[36:38], uint16(len(user)))
		le.PutUint16(amsg[38:40], uint16(len(user)))
		le.PutUint32(amsg[40:44], uint32(off))
		off += copy(amsg[off:], user)
	}

	if workstation != nil {
		le.PutUint16(amsg[44:46], uint16(len(workstation)))
		le.PutUint16(amsg[46:48], uint16(len(workstation)))
		le.PutUint32(amsg[48:52], uint32(off))
		off += copy(amsg[off:], workstation)
	}

	if c.User != "" || c.Password != "" {
		var err error

		USER := c.encodeString(strings.ToUpper(c.User))
		password := c.encodeString(c.Password)

		h := hmac.New(md5.New, ntowfv2(USER, password, domain))

		//        LMv2Response
		//  0-16: Response
		// 16-24: ChallengeFromClient

		lmChallengeResponse := amsg[off : off+24]
		{
			le.PutUint16(amsg[12:14], uint16(len(lmChallengeResponse)))
			le.PutUint16(amsg[14:16], uint16(len(lmChallengeResponse)))
			le.PutUint32(amsg[16:20], uint32(off))

			off += 24
		}

		//        NTLMv2Response
		//  0-16: Response
		//   16-: NTLMv2ClientChallenge

		ntChallengeResponse := amsg[off : len(amsg)-16]
		{
			ntlmv2ClientChallenge := ntChallengeResponse[16:]

			serverChallenge := cmsg[24:32]

			clientChallenge := ntlmv2ClientChallenge[16:24]

			_, err := rand.Read(clientChallenge)
			if err != nil {
				return nil, err
			}

			timeStamp, ok := info.InfoMap[MsvAvTimestamp]
			if !ok {
				timeStamp = ntlmv2ClientChallenge[8:16]
				le.PutUint64(timeStamp, uint64((time.Now().UnixNano()/100)+116444736000000000))
			}

			encodeNtlmv2Response(ntChallengeResponse, h, serverChallenge, clientChallenge, timeStamp, info)

			le.PutUint16(amsg[20:22], uint16(len(ntChallengeResponse)))
			le.PutUint16(amsg[22:24], uint16(len(ntChallengeResponse)))
			le.PutUint32(amsg[24:28], uint32(off))

			off = len(amsg) - 16
		}

		h.Reset()
		h.Write(ntChallengeResponse[:16])
		sessionBaseKey := h.Sum(nil)

		keyExchangeKey := sessionBaseKey // if ntlm version == 2

		if c.negotiateFlags&NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
			c.exportedSessionKey = make([]byte, 16)
			_, err := rand.Read(c.exportedSessionKey)
			if err != nil {
				return nil, err
			}
			cipher, err := rc4.NewCipher(keyExchangeKey)
			if err != nil {
				return nil, err
			}
			encryptedRandomSessionKey := amsg[off:]
			cipher.XORKeyStream(encryptedRandomSessionKey, c.exportedSessionKey)

			le.PutUint16(amsg[52:54], 16)          // amsg.EncryptedRandomSessionKeyLen
			le.PutUint16(amsg[54:56], 16)          // amsg.EncryptedRandomSessionKeyMaxLen
			le.PutUint32(amsg[56:60], uint32(off)) // amsg.EncryptedRandomSessionKeyBufferOffset
		} else {
			c.exportedSessionKey = keyExchangeKey
		}

		le.PutUint32(amsg[60:64], c.negotiateFlags)

		if useVersion {
			copy(amsg[64:], version)
			if useMIC {
				if nmsg != nil {
					h := hmac.New(md5.New, c.exportedSessionKey)
					h.Write(nmsg)
					h.Write(cmsg)
					h.Write(amsg)
					h.Sum(amsg[:72]) // amsg.MIC
				}
			}
		} else {
			if useMIC {
				if nmsg != nil {
					h := hmac.New(md5.New, c.exportedSessionKey)
					h.Write(nmsg)
					h.Write(cmsg)
					h.Write(amsg)
					h.Sum(amsg[:64]) // amsg.MIC
				}
			}
		}

		{
			c.clientSigningKey = signKey(c.negotiateFlags, c.exportedSessionKey, true)
			c.serverSigningKey = signKey(c.negotiateFlags, c.exportedSessionKey, false)

			c.clientHandle, err = rc4.NewCipher(sealKey(c.negotiateFlags, c.exportedSessionKey, true))
			if err != nil {
				return nil, err
			}

			c.serverHandle, err = rc4.NewCipher(sealKey(c.negotiateFlags, c.exportedSessionKey, false))
			if err != nil {
				return nil, err
			}
		}
	}

	c.state = 2

	return amsg, nil
}

func (c *Client) SessionKey() []byte {
	if c.state != 2 {
		panic("bad state")
	}
	return c.exportedSessionKey
}

func (c *Client) Overhead() int {
	return 16
}

func (c *Client) Sum(plaintext []byte, seqNum uint32) ([]byte, uint32) {
	if c.state != 2 {
		panic("bad state")
	}

	if c.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		return nil, 0
	}

	return mac(nil, c.negotiateFlags, c.clientHandle, c.clientSigningKey, seqNum, plaintext)
}

func (c *Client) CheckSum(sum, plaintext []byte, seqNum uint32) (bool, uint32) {
	if c.state != 2 {
		panic("bad state")
	}

	if c.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		if sum == nil {
			return true, 0
		}
		return false, 0
	}

	ret, seqNum := mac(nil, c.negotiateFlags, c.serverHandle, c.serverSigningKey, seqNum, plaintext)
	if !bytes.Equal(sum, ret) {
		return false, 0
	}
	return true, seqNum
}

func (c *Client) Seal(dst, plaintext []byte, seqNum uint32) ([]byte, uint32) {
	if c.state != 2 {
		panic("bad state")
	}

	ret, ciphertext := sliceForAppend(dst, len(plaintext)+16)

	switch {
	case c.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		c.clientHandle.XORKeyStream(ciphertext[16:], plaintext)

		_, seqNum = mac(ciphertext[:0], c.negotiateFlags, c.clientHandle, c.clientSigningKey, seqNum, plaintext)
	case c.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(ciphertext[16:], plaintext)

		_, seqNum = mac(ciphertext[:0], c.negotiateFlags, c.clientHandle, c.clientSigningKey, seqNum, plaintext)
	}

	return ret, seqNum
}

func (c *Client) Unseal(dst, ciphertext []byte, seqNum uint32) ([]byte, uint32, error) {
	if c.state != 2 {
		panic("bad state")
	}

	ret, plaintext := sliceForAppend(dst, len(ciphertext)-16)

	switch {
	case c.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		c.serverHandle.XORKeyStream(plaintext, ciphertext[16:])

		var sum []byte

		sum, seqNum = mac(nil, c.negotiateFlags, c.serverHandle, c.serverSigningKey, seqNum, plaintext)
		if !bytes.Equal(ciphertext[:16], sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	case c.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(plaintext, ciphertext[16:])

		var sum []byte

		sum, seqNum = mac(nil, c.negotiateFlags, c.serverHandle, c.serverSigningKey, seqNum, plaintext)
		if !bytes.Equal(ciphertext[:16], sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	default:
		copy(plaintext, ciphertext[16:])
		for _, c := range ciphertext[:16] {
			if c != 0x0 {
				return nil, 0, errors.New("signature mismatch")
			}
		}
	}

	return ret, seqNum, nil
}

func (c *Client) encodeString(s string) []byte {
	switch c.negotiateFlags & (NTLM_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_UNICODE) {
	case NTLMSSP_NEGOTIATE_UNICODE:
		return utf16BytesFromString(s)
	case NTLM_NEGOTIATE_OEM:
		return []byte(s)
	default: // invalid, but return
		return []byte(s)
	}
}
