package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

func TestNtowfv2(t *testing.T) {
	USER := utf16le.EncodeStringToBytes("USER")
	password := utf16le.EncodeStringToBytes("Password")
	domain := utf16le.EncodeStringToBytes("Domain")
	ntlmv2Hash, err := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if err != nil {
		t.Fatal(err)
	}

	ret := ntowfv2(USER, password, domain)

	if !bytes.Equal(ret, ntlmv2Hash) {
		t.Errorf("expected %v, got %v", ntlmv2Hash, ret)
	}
}

func TestTargetInfoRejectsShortMsvAvFlags(t *testing.T) {
	info := make([]byte, 8)
	binary.LittleEndian.PutUint16(info[0:2], MsvAvFlags)
	// MsvAvFlags must contain a four-byte value, but this pair is empty.
	binary.LittleEndian.PutUint16(info[2:4], 0)

	if encoder := newTargetInfoEncoder(info, nil); encoder != nil {
		t.Fatal("target info with a short MsvAvFlags value was accepted")
	}
}

func TestTargetInfoRejectsInvalidEOL(t *testing.T) {
	tests := []struct {
		name string
		info []byte
	}{
		{
			name: "missing EOL after zero flags value",
			info: []byte{0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "nonzero EOL length",
			info: []byte{0x00, 0x00, 0x01, 0x00, 0xaa},
		},
		{
			name: "EOL followed by a pair",
			info: []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
		},
		{
			name: "EOL in the middle of pairs",
			info: append(
				testAvPair(MsvAvNbDomainName, []byte{0xaa}),
				append(testAvPair(MsvAvEOL, nil), testAvPair(MsvAvFlags, nil)...)...,
			),
		},
		{
			name: "EOL followed by zero padding",
			info: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "truncated value",
			info: []byte{0x01, 0x00, 0x04, 0x00, 0xaa},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if encoder := newTargetInfoEncoder(test.info, nil); encoder != nil {
				t.Fatal("invalid target info was accepted")
			}
		})
	}
}

func TestTargetInfoEncoderPreservesPairs(t *testing.T) {
	const domainID = uint16(MsvAvNbDomainName)
	domain := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	tests := []struct {
		name          string
		info          []byte
		wantFlags     uint32
		wantDomain    []byte
		wantFlagOrder bool
	}{
		{
			name:      "EOL only",
			info:      testAvPair(MsvAvEOL, nil),
			wantFlags: 0x02,
		},
		{
			name:          "adds flags after existing pair",
			info:          append(testAvPair(domainID, domain), testAvPair(MsvAvEOL, nil)...),
			wantFlags:     0x02,
			wantDomain:    domain,
			wantFlagOrder: true,
		},
		{
			name: "updates zero flags before EOL",
			info: append(
				testAvPair(domainID, domain),
				append(testAvPair(MsvAvFlags, []byte{0, 0, 0, 0}), testAvPair(MsvAvEOL, nil)...)...,
			),
			wantFlags:  0x02,
			wantDomain: domain,
		},
		{
			name: "updates flags in place",
			info: append(
				testAvPair(MsvAvFlags, []byte{0x01, 0x00, 0x00, 0x00}),
				append(testAvPair(domainID, domain), testAvPair(MsvAvEOL, nil)...)...,
			),
			wantFlags:  0x03,
			wantDomain: domain,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoder := newTargetInfoEncoder(test.info, nil)
			if encoder == nil {
				t.Fatal("valid target info was rejected")
			}

			encoded := make([]byte, encoder.size())
			encoder.encode(encoded)
			pairs, ok := parseAvPairs(encoded)
			if !ok {
				t.Fatal("encoded target info could not be parsed")
			}
			if eol, ok := pairs[MsvAvEOL]; !ok || len(eol) != 0 {
				t.Errorf("expected empty EOL value, got %x", eol)
			}

			flags, ok := pairs[MsvAvFlags]
			if !ok || len(flags) != 4 {
				t.Fatalf("expected four-byte flags value, got %x", flags)
			}
			if value := binary.LittleEndian.Uint32(flags); value != test.wantFlags {
				t.Errorf("expected flags %#x, got %#x", test.wantFlags, value)
			}
			if test.wantDomain != nil && !bytes.Equal(pairs[domainID], test.wantDomain) {
				t.Errorf("expected domain %x, got %x", test.wantDomain, pairs[domainID])
			}
			if test.wantFlagOrder && !bytes.HasPrefix(encoded, test.info[:len(test.info)-4]) {
				t.Fatal("new flags pair was not appended after existing pairs")
			}
		})
	}
}

func testAvPair(id uint16, value []byte) []byte {
	pair := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(pair[:2], id)
	binary.LittleEndian.PutUint16(pair[2:4], uint16(len(value)))
	copy(pair[4:], value)
	return pair
}

func TestTargetInfoEncodeDoesNotMutateChallenge(t *testing.T) {
	info := make([]byte, 12)
	binary.LittleEndian.PutUint16(info[0:2], MsvAvFlags)
	binary.LittleEndian.PutUint16(info[2:4], 4)
	binary.LittleEndian.PutUint32(info[4:8], 0)
	original := append([]byte(nil), info...)

	encoder := newTargetInfoEncoder(info, nil)
	if encoder == nil {
		t.Fatal("valid target info was rejected")
	}
	encoder.encode(make([]byte, encoder.size()))

	if !bytes.Equal(info, original) {
		t.Fatal("target info encoder mutated the server challenge")
	}
}

func TestTargetInfoEncodeKeepsFlagsValueAndRecords(t *testing.T) {
	spn := utf16le.EncodeStringToBytes("cifs/server")
	info := []byte{
		0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // MsvAvFlags = 0
		0x00, 0x00, 0x00, 0x00, // MsvAvEOL
	}

	encoder := newTargetInfoEncoder(info, spn)
	if encoder == nil {
		t.Fatal("valid target info was rejected")
	}

	dst := make([]byte, encoder.size())
	encoder.encode(dst)

	if id := le.Uint16(dst[0:2]); id != MsvAvFlags {
		t.Fatalf("first AvId = %#x, want MsvAvFlags", id)
	}
	if flags := le.Uint32(dst[4:8]); flags&0x02 == 0 {
		t.Fatalf("MsvAvFlags value = %#x, want MIC bit set", flags)
	}
	if id := le.Uint16(dst[8:10]); id != MsvAvChannelBindings {
		t.Fatalf("AvId after MsvAvFlags = %#x, want MsvAvChannelBindings", id)
	}
	if id := le.Uint16(dst[28:30]); id != MsvAvTargetName {
		t.Fatalf("AvId after MsvAvChannelBindings = %#x, want MsvAvTargetName", id)
	}
	if got := dst[32 : 32+len(spn)]; !bytes.Equal(got, spn) {
		t.Fatalf("MsvAvTargetName = %x, want %x", got, spn)
	}
}

func TestClientAuthenticateRejectsTargetInfoWithoutEOL(t *testing.T) {
	c := &Client{}
	nmsg, err := c.Negotiate()
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer("server")
	cmsg, err := s.Challenge(nmsg)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the trailing MsvAvEOL with an MsvAvFlags pair whose zero value
	// must not be mistaken for the end of the list.
	invalid := []byte{0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	targetInfoOffset := le.Uint32(cmsg[44:48])
	cmsg = append(cmsg[:targetInfoOffset], invalid...)
	le.PutUint16(cmsg[40:42], uint16(len(invalid)))
	le.PutUint16(cmsg[42:44], uint16(len(invalid)))

	if _, err := c.Authenticate(cmsg); err == nil {
		t.Fatal("Authenticate accepted target info without MsvAvEOL")
	}
}

type simpleEncoder []byte

func (s simpleEncoder) size() int {
	return len(s)
}

func (s simpleEncoder) encode(bs []byte) {
	copy(bs, s)
}

func TestNtlmv2ClientChallenge(t *testing.T) {
	ntlmv2Hash, err := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if err != nil {
		t.Fatal(err)
	}
	serverChallenge, err := hex.DecodeString("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	clientChallenge, err := hex.DecodeString("aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	timestamp, err := hex.DecodeString("0000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	targetInfo, err := hex.DecodeString(
		"0200" + "0c00" + "44006f006d00610069006e00" + // MsvAvNbDomainName + dataLen + data
			"0100" + "0c00" + "530065007200760065007200" + // MsvAvNbComputerName + dataLen + data
			"0000" + "0000") // MsvAvEOL + dataLen
	if err != nil {
		t.Fatal(err)
	}
	temp, err := hex.DecodeString("01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	ntlmv2Response, err := hex.DecodeString("68cd0ab851e51c96aabc927bebef6a1c")
	if err != nil {
		t.Fatal(err)
	}

	h := hmac.New(md5.New, ntlmv2Hash)

	ret := make([]byte, 16+28+len(targetInfo)+4)
	encodeNtlmv2Response(ret, h, serverChallenge, clientChallenge, timestamp, simpleEncoder(targetInfo))

	if !bytes.Equal(ret[16:], temp) {
		t.Errorf("expected %v, got %v", temp, ret[16:])
	}

	if !bytes.Equal(ret[:16], ntlmv2Response) {
		t.Errorf("expected %v, got %v", ntlmv2Response, ret[:16])
	}
}

func TestSessionBaseKey(t *testing.T) {
	ntlmv2Hash, err := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if err != nil {
		t.Fatal(err)
	}

	ntlmv2Response, err := hex.DecodeString("68cd0ab851e51c96aabc927bebef6a1c")
	if err != nil {
		t.Fatal(err)
	}

	sessionBaseKey, err := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	if err != nil {
		t.Fatal(err)
	}

	h := hmac.New(md5.New, ntlmv2Hash)
	h.Write(ntlmv2Response)
	ret := h.Sum(nil)

	if !bytes.Equal(ret, sessionBaseKey) {
		t.Errorf("expected %v, got %v", sessionBaseKey, ret)
	}
}

func TestEncryptedSessionKey(t *testing.T) {
	randomSessionKey, err := hex.DecodeString("55555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	sessionBaseKey, err := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	if err != nil {
		t.Fatal(err)
	}
	encryptedSessionKey, err := hex.DecodeString("c5dad2544fc9799094ce1ce90bc9d03e")
	if err != nil {
		t.Fatal(err)
	}

	keyExchangeKey := sessionBaseKey

	cipher, err := rc4.NewCipher(keyExchangeKey)
	if err != nil {
		t.Fatal(err)
	}

	ret := make([]byte, 16)

	cipher.XORKeyStream(ret, randomSessionKey)

	if !bytes.Equal(ret, encryptedSessionKey) {
		t.Errorf("expected %v, got %v", encryptedSessionKey, ret)
	}
}

func TestSealKey(t *testing.T) {
	randomSessionKey, err := hex.DecodeString("55555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	clientSealKey, err := hex.DecodeString("59f600973cc4960a25480a7c196e4c58")
	if err != nil {
		t.Fatal(err)
	}

	ret := sealKey(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|NTLMSSP_NEGOTIATE_128, randomSessionKey, true)

	if !bytes.Equal(ret, clientSealKey) {
		t.Errorf("expected %v, got %v", clientSealKey, ret)
	}
}

func TestSignKey(t *testing.T) {
	randomSessionKey, err := hex.DecodeString("55555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	clientSignKey, err := hex.DecodeString("4788dc861b4782f35d43fd98fe1a2d39")
	if err != nil {
		t.Fatal(err)
	}

	ret := signKey(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, randomSessionKey, true)

	if !bytes.Equal(ret, clientSignKey) {
		t.Errorf("expected %v, got %v", clientSignKey, ret)
	}
}

func TestSeal(t *testing.T) {
	seqNum := uint32(0)
	clientSealKey, err := hex.DecodeString("59f600973cc4960a25480a7c196e4c58")
	if err != nil {
		t.Fatal(err)
	}
	clientSignKey, err := hex.DecodeString("4788dc861b4782f35d43fd98fe1a2d39")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString("54e50165bf1936dc996020c1811b0f06fb5f")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString("010000007fb38ec5c55d497600000000")
	if err != nil {
		t.Fatal(err)
	}
	clientHandle, err := rc4.NewCipher(clientSealKey)
	if err != nil {
		t.Fatal(err)
	}
	plainText := utf16le.EncodeStringToBytes("Plaintext")
	ret := make([]byte, len(plainText)+16)
	clientHandle.XORKeyStream(ret[16:], plainText)
	mac(ret[:0], NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|NTLMSSP_NEGOTIATE_KEY_EXCH, clientHandle, clientSignKey, seqNum, plainText)

	if !bytes.Equal(ret[16:], data) {
		t.Errorf("expected %v, got %v", data, ret[16:])
	}

	if !bytes.Equal(ret[:16], signature) {
		t.Errorf("expected %v, got %v", signature, ret[:16])
	}
}

func authenticatedSessions(t *testing.T) (*Session, *Session) {
	t.Helper()

	c := &Client{User: "user", Password: "password"}
	s := NewServer("server")
	s.AddAccount("user", "password")

	nmsg, err := c.Negotiate()
	if err != nil {
		t.Fatal(err)
	}
	cmsg, err := s.Challenge(nmsg)
	if err != nil {
		t.Fatal(err)
	}
	amsg, err := c.Authenticate(cmsg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Authenticate(amsg); err != nil {
		t.Fatal(err)
	}
	return c.Session(), s.Session()
}

func TestSessionSealUnseal(t *testing.T) {
	for _, mode := range []struct {
		name string
		seal bool
	}{
		{name: "signed"},
		{name: "sealed", seal: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			client, server := authenticatedSessions(t)
			if mode.seal {
				// Enable sealing only for these tests; negotiation defaults omit it.
				client.negotiateFlags |= NTLMSSP_NEGOTIATE_SEAL
				server.negotiateFlags |= NTLMSSP_NEGOTIATE_SEAL
			}
			directions := []struct {
				name     string
				sender   *Session
				receiver *Session
				sendSeq  uint32
				recvSeq  uint32
			}{
				{name: "client to server", sender: client, receiver: server},
				{name: "server to client", sender: server, receiver: client},
			}
			for round := range 3 {
				for i := range directions {
					direction := &directions[i]
					plaintext := []byte(direction.name + " message " + strconv.Itoa(round))
					ciphertext, sendSeq := direction.sender.Seal(nil, plaintext, direction.sendSeq)
					if !mode.seal && !bytes.Equal(ciphertext[16:], plaintext) {
						t.Fatal("signing-only Seal changed the message body")
					}
					unsealed, recvSeq, err := direction.receiver.Unseal(nil, ciphertext, direction.recvSeq)
					if err != nil {
						t.Fatalf("%s round %d: %v", direction.name, round, err)
					}
					if !bytes.Equal(unsealed, plaintext) {
						t.Fatalf("%s round %d: plaintext = %q, want %q", direction.name, round, unsealed, plaintext)
					}
					if sendSeq != direction.sendSeq+1 || recvSeq != sendSeq {
						t.Fatalf("%s round %d: send sequence = %d, receive sequence = %d, want %d", direction.name, round, sendSeq, recvSeq, direction.sendSeq+1)
					}
					direction.sendSeq, direction.recvSeq = sendSeq, recvSeq
				}
			}
		})
	}
}

func TestSessionUnsealRejectsModifiedSignature(t *testing.T) {
	for _, fromClient := range []bool{true, false} {
		name := "server to client"
		if fromClient {
			name = "client to server"
		}
		t.Run(name, func(t *testing.T) {
			// Use fresh sessions for each tampered message.
			client, server := authenticatedSessions(t)
			client.negotiateFlags |= NTLMSSP_NEGOTIATE_SEAL
			server.negotiateFlags |= NTLMSSP_NEGOTIATE_SEAL
			sender, receiver := server, client
			if fromClient {
				sender, receiver = client, server
			}
			ciphertext, _ := sender.Seal(nil, []byte("message"), 0)
			ciphertext[4] ^= 1
			if _, _, err := receiver.Unseal(nil, ciphertext, 0); err == nil || err.Error() != "signature mismatch" {
				t.Fatalf("Unseal error = %v, want signature mismatch", err)
			}
		})
	}
}

func unsealSessionsForTest(t *testing.T, flags uint32) (*Session, *Session) {
	t.Helper()
	key := bytes.Repeat([]byte{0x55}, 16)
	newHandle := func() *rc4.Cipher {
		handle, err := rc4.NewCipher(sealKey(flags, key, false))
		if err != nil {
			t.Fatal(err)
		}
		return handle
	}
	// Match the sender's outgoing stream to the receiver's incoming stream.
	sender := &Session{
		isClientSide:     true,
		negotiateFlags:   flags,
		clientHandle:     newHandle(),
		clientSigningKey: signKey(flags, key, false),
	}
	receiver := &Session{
		isClientSide:     true,
		negotiateFlags:   flags,
		serverHandle:     newHandle(),
		serverSigningKey: signKey(flags, key, false),
	}
	return sender, receiver
}

func TestUnsealRejectsShortMessages(t *testing.T) {
	for _, mode := range []struct {
		name  string
		flags uint32
	}{
		{name: "zero"},
		{name: "signed", flags: NTLMSSP_NEGOTIATE_SIGN},
		{name: "sealed", flags: NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL},
	} {
		for _, length := range []int{0, 1, 15} {
			for _, dstLength := range []int{0, 7} {
				t.Run(mode.name+"/"+strconv.Itoa(length)+"/dst="+strconv.Itoa(dstLength), func(t *testing.T) {
					var sender, receiver, control *Session
					if mode.flags == 0 {
						receiver = &Session{}
					} else {
						flags := mode.flags | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_KEY_EXCH
						sender, receiver = unsealSessionsForTest(t, flags)
						_, control = unsealSessionsForTest(t, flags)
					}
					var backing, dst []byte
					if dstLength != 0 {
						backing = bytes.Repeat([]byte{0xa5}, 64)
						dst = backing[:dstLength]
					}
					original := append([]byte(nil), backing...)
					seqNum := uint32(42)
					got, next, err := receiver.Unseal(dst, make([]byte, length), seqNum)
					if err == nil || err.Error() != "invalid sealed message length" {
						t.Fatalf("Unseal error = %v, want invalid sealed message length", err)
					}
					if got != nil || next != seqNum {
						t.Fatalf("Unseal = (%x, %d), want (nil, %d)", got, next, seqNum)
					}
					if !bytes.Equal(backing, original) {
						t.Fatal("short message changed destination backing array")
					}
					if mode.flags == 0 {
						return
					}
					for _, plaintext := range [][]byte{nil, []byte("message after rejection")} {
						ciphertext, wantSeq := sender.Seal(nil, plaintext, seqNum)
						if len(ciphertext) != 16+len(plaintext) {
							t.Fatalf("sealed message length = %d, want %d", len(ciphertext), 16+len(plaintext))
						}
						want, controlSeq, err := control.Unseal(append([]byte(nil), dst...), ciphertext, seqNum)
						if err != nil || controlSeq != wantSeq {
							t.Fatalf("control Unseal sequence = %d, error = %v", controlSeq, err)
						}
						got, next, err = receiver.Unseal(dst, ciphertext, seqNum)
						if err != nil || next != controlSeq || !bytes.Equal(got, want) {
							t.Fatalf("Unseal after rejection = (%x, %d, %v), want (%x, %d, nil)", got, next, err, want, controlSeq)
						}
						if !bytes.Equal(got[:len(dst)], original[:len(dst)]) || !bytes.Equal(got[len(dst):], plaintext) {
							t.Fatalf("Unseal did not preserve prefix and recover plaintext: %x", got)
						}
						seqNum = next
					}
				})
			}
		}
	}
}

func TestUnsealRejectsInvalidSignature(t *testing.T) {
	for _, flags := range []uint32{NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL} {
		for _, plaintext := range [][]byte{nil, []byte("message")} {
			sender, receiver := unsealSessionsForTest(t, flags|NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|NTLMSSP_NEGOTIATE_KEY_EXCH)
			ciphertext, _ := sender.Seal(nil, plaintext, 42)
			ciphertext[0] ^= 1
			got, next, err := receiver.Unseal(nil, ciphertext, 42)
			if err == nil || err.Error() != "signature mismatch" || got != nil || next != 0 {
				t.Fatalf("Unseal = (%x, %d, %v), want (nil, 0, signature mismatch)", got, next, err)
			}
		}
	}
}

func TestClientServer(t *testing.T) {
	tests := []struct {
		name            string
		user            string
		pass            string
		account         bool
		accountPassword string
		wantSuccess     bool
	}{
		{"authenticated", "user", "password", true, "password", true},
		{"explicit empty password", "empty-password", "", true, "", true},
		{"wrong password", "user", "wrong", true, "password", false},
		{"anonymous", "", "", false, "", true},
		{"unregistered empty password", "unregistered", "", false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				User:     tt.user,
				Password: tt.pass,
			}

			s := NewServer("server")
			if tt.account {
				s.AddAccount(tt.user, tt.accountPassword)
			}

			nmsg, err := c.Negotiate()
			if err != nil {
				t.Fatal(err)
			}

			cmsg, err := s.Challenge(nmsg)
			if err != nil {
				t.Fatal(err)
			}

			amsg, err := c.Authenticate(cmsg)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Authenticate(amsg)
			if tt.wantSuccess {
				if err != nil {
					t.Fatal(err)
				}
				if c.Session() == nil || s.Session() == nil {
					t.Error("authentication did not establish both sessions")
				}
			} else {
				if err == nil {
					t.Error("authentication unexpectedly succeeded")
				}
				if s.Session() != nil {
					t.Error("authentication established a server session")
				}
			}
		})
	}
}

func challengeMessageForTest(t *testing.T) ([]byte, []byte) {
	t.Helper()

	c := &Client{}
	nmsg, err := c.Negotiate()
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer("server")
	cmsg, err := s.Challenge(nmsg)
	if err != nil {
		t.Fatal(err)
	}

	return cmsg, nmsg
}

func TestUnmarshalChallengeMessageNegotiateMessageLength(t *testing.T) {
	cmsg, nmsg := challengeMessageForTest(t)
	tests := []struct {
		length  int
		wantErr bool
	}{
		{length: 0, wantErr: true},
		{length: 1, wantErr: true},
		{length: 2, wantErr: true},
		{length: 3, wantErr: true},
		{length: 4, wantErr: true},
		{length: 5, wantErr: true},
		{length: 6, wantErr: true},
		{length: 7, wantErr: true},
		{length: 8, wantErr: true},
		{length: 9, wantErr: true},
		{length: 10, wantErr: true},
		{length: 11, wantErr: true},
		{length: 12, wantErr: true},
		{length: 13, wantErr: true},
		{length: 14, wantErr: true},
		{length: 15, wantErr: true},
		{length: 16, wantErr: false},
	}

	for _, tc := range tests {
		t.Run(strconv.Itoa(tc.length), func(t *testing.T) {
			for _, capacity := range []int{tc.length, 16} {
				_, err := UnmarshalChallengeMessage(cmsg, nmsg[:tc.length:capacity], "")
				if (err != nil) != tc.wantErr {
					t.Errorf("capacity %d: error = %v, wantErr %v", capacity, err, tc.wantErr)
				}
			}
		})
	}
}

func TestAuthenticateRejectsBeforeNegotiate(t *testing.T) {
	cmsg, _ := challengeMessageForTest(t)

	if _, err := (&Client{}).Authenticate(cmsg); err == nil {
		t.Fatal("Authenticate accepted a challenge before Negotiate")
	}
}

type authenticateField struct {
	name      string
	length    int
	maxLength int
	offset    int
}

var authenticateFields = []authenticateField{
	{name: "nt challenge response", length: 20, maxLength: 22, offset: 24},
	{name: "domain name", length: 28, maxLength: 30, offset: 32},
	{name: "user name", length: 36, maxLength: 38, offset: 40},
	{name: "encrypted session key", length: 52, maxLength: 54, offset: 56},
	{name: "lm challenge response", length: 12, maxLength: 14, offset: 16},
	{name: "workstation", length: 44, maxLength: 46, offset: 48},
}

func authenticatedMessage(t *testing.T) ([]byte, *Server) {
	t.Helper()

	c := &Client{User: "user", Password: "password"}
	s := NewServer("server")
	s.AddAccount("user", "password")

	nmsg, err := c.Negotiate()
	if err != nil {
		t.Fatal(err)
	}
	cmsg, err := s.Challenge(nmsg)
	if err != nil {
		t.Fatal(err)
	}
	amsg, err := c.Authenticate(cmsg)
	if err != nil {
		t.Fatal(err)
	}
	return amsg, s
}

func authenticateMustReturnError(t *testing.T, s *Server, amsg []byte) {
	t.Helper()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("Authenticate panicked: %v", recovered)
		}
	}()

	if err := s.Authenticate(amsg); err == nil {
		t.Error("Authenticate accepted malformed message")
	}
}

func setAuthenticateField(amsg []byte, field authenticateField, length uint16, offset uint32) {
	le.PutUint16(amsg[field.length:], length)
	le.PutUint16(amsg[field.maxLength:], length)
	le.PutUint32(amsg[field.offset:], offset)
}

func TestUnmarshalChallengeMessageRejectsHeaderOffsets(t *testing.T) {
	cmsg, nmsg := challengeMessageForTest(t)

	// Corrupt TargetName offset to point into header (offset 10)
	cmsgBadTarget := append([]byte(nil), cmsg...)
	le.PutUint32(cmsgBadTarget[16:20], 10)
	if _, err := UnmarshalChallengeMessage(cmsgBadTarget, nmsg, ""); err == nil {
		t.Error("UnmarshalChallengeMessage accepted TargetName offset inside fixed header")
	}

	// Corrupt TargetInfo offset to point into header (offset 20)
	cmsgBadInfo := append([]byte(nil), cmsg...)
	le.PutUint32(cmsgBadInfo[44:48], 20)
	if _, err := UnmarshalChallengeMessage(cmsgBadInfo, nmsg, ""); err == nil {
		t.Error("UnmarshalChallengeMessage accepted TargetInfo offset inside fixed header")
	}
}

func TestAuthenticateRejectsOutOfRangeSecurityBuffers(t *testing.T) {
	cases := []struct {
		name       string
		length     uint16
		offsetFunc func(int) uint32
	}{
		{
			name:   "inside fixed header",
			length: 4,
			offsetFunc: func(int) uint32 {
				return 10
			},
		},
		{
			name:   "inside version or mic",
			length: 4,
			offsetFunc: func(int) uint32 {
				return 72
			},
		},
		{
			name:   "range overrun",
			length: 2,
			offsetFunc: func(messageLength int) uint32 {
				return uint32(messageLength - 1)
			},
		},
		{
			name:   "uint32 addition wraparound",
			length: 4,
			offsetFunc: func(int) uint32 {
				return ^uint32(0) - 2
			},
		},
		{
			name:   "message boundary",
			length: 1,
			offsetFunc: func(messageLength int) uint32 {
				return uint32(messageLength - 1)
			},
		},
	}

	for _, tc := range cases {
		for _, field := range authenticateFields {
			t.Run(tc.name+"/"+field.name, func(t *testing.T) {
				amsg, s := authenticatedMessage(t)
				setAuthenticateField(amsg, field, tc.length, tc.offsetFunc(len(amsg)))
				authenticateMustReturnError(t, s, amsg)
			})
		}
	}
}

func TestAuthenticateRejectsShortNtChallengeResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length uint16
	}{
		{name: "zero", length: 0},
		{name: "15", length: 15},
		{name: "16", length: 16},
		{name: "39", length: 39},
		{name: "43", length: 43},
	} {
		t.Run(tc.name, func(t *testing.T) {
			amsg, s := authenticatedMessage(t)
			setAuthenticateField(amsg, authenticateFields[0], tc.length, 112)
			authenticateMustReturnError(t, s, amsg)
		})
	}
}

func TestAuthenticateRejectsMissingMIC(t *testing.T) {
	tests := []struct {
		name       string
		messageLen int
		flags      uint32
	}{
		{name: "without version", messageLen: 64, flags: defaultFlags &^ (NTLMSSP_NEGOTIATE_VERSION | NTLMSSP_NEGOTIATE_KEY_EXCH)},
		{name: "with version", messageLen: 80, flags: defaultFlags &^ NTLMSSP_NEGOTIATE_KEY_EXCH},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			amsg, s := authenticatedMessage(t)
			amsg = amsg[:tc.messageLen]
			for _, field := range authenticateFields {
				setAuthenticateField(amsg, field, 0, uint32(tc.messageLen))
			}
			le.PutUint32(amsg[60:64], tc.flags)
			authenticateMustReturnError(t, s, amsg)
		})
	}
}

func TestAuthenticateRejectsWithoutChallenge(t *testing.T) {
	amsg, _ := authenticatedMessage(t)

	s := NewServer("server")
	s.AddAccount("user", "password")
	authenticateMustReturnError(t, s, amsg)
}

func TestAuthenticateRejectsInvalidKeyExchangeLength(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length uint16
	}{
		{name: "zero", length: 0},
		{name: "15", length: 15},
		{name: "17", length: 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			amsg, s := authenticatedMessage(t)
			if tc.length == 17 {
				amsg = append(amsg, 0)
			}
			keyOffset := len(amsg) - int(tc.length)
			setAuthenticateField(amsg, authenticateFields[3], tc.length, uint32(keyOffset))
			authenticateMustReturnError(t, s, amsg)
		})
	}
}
