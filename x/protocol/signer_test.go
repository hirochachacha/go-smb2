package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestGMACKnownAnswerAndNonce(t *testing.T) {
	g, err := newGMAC(make([]byte, 16))
	require.NoError(t, err)
	tag, err := g.sum([12]byte{}, nil)
	require.NoError(t, err)
	require.Equal(t, "58e2fccefa7e3061367f1d57a4e7455a", hex.EncodeToString(tag[:]))
	for _, tc := range []struct {
		command wire.Command
		flags   uint32
		tail    uint32
	}{
		{wire.SMB2_WRITE, 0, 0}, {wire.SMB2_READ, wire.SMB2_FLAGS_SERVER_TO_REDIR, 1},
		{wire.SMB2_CANCEL, 0, 2}, {wire.SMB2_CANCEL, wire.SMB2_FLAGS_ASYNC_COMMAND, 2},
		{wire.SMB2_READ, wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_ASYNC_COMMAND, 1},
	} {
		p := wire.PacketCodec(make([]byte, 64))
		p.SetMessageId(0x0102030405060708)
		p.SetCommand(tc.command)
		p.SetFlags(tc.flags)
		n := gmacNonce(p, tc.flags&wire.SMB2_FLAGS_SERVER_TO_REDIR != 0)
		require.Equal(t, []byte{8, 7, 6, 5, 4, 3, 2, 1}, n[:8])
		require.Equal(t, tc.tail, binary.LittleEndian.Uint32(n[8:]))
	}
}

func TestSessionGMACSegmentsAndScope(t *testing.T) {
	s := &session{conn: &conn{dialect: wire.SMB311, signingAlgorithm: wire.AES128GMAC}}
	require.NoError(t, s.setupKeys(make([]byte, 16)))
	require.NotSame(t, s.signer, s.verifier)
	packet := make([]byte, 112+259+5) // WRITE plus payload and compound alignment padding.
	p := wire.PacketCodec(packet)
	p.SetProtocolId()
	p.SetCommand(wire.SMB2_WRITE)
	p.SetMessageId(7)
	for i := 64; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	key := kdf(make([]byte, 16), []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:], 16)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	oracle, err := cipher.NewGCM(block)
	require.NoError(t, err)
	unsigned := append([]byte(nil), packet...)
	u := wire.PacketCodec(unsigned)
	u.SetFlags(wire.SMB2_FLAGS_SIGNED)
	nonce := gmacNonce(u, false)
	want := oracle.Seal(nil, nonce[:], nil, unsigned)
	for _, cut := range []int{64, 65, 79, 80, 111, 112, 113, len(packet) - 1, len(packet)} {
		b := append([]byte(nil), packet...)
		_, err = s.sign(b[:cut], nil, b[cut:])
		require.NoError(t, err)
		require.Equal(t, want, wire.PacketCodec(b).Signature())
		clear(b[48:64])
		bp := wire.PacketCodec(b)
		bp.SetFlags(bp.Flags() | wire.SMB2_FLAGS_SERVER_TO_REDIR)
		serverNonce := gmacNonce(bp, true)
		copy(b[48:64], oracle.Seal(nil, serverNonce[:], nil, b))
		require.True(t, s.verify(b[:cut], b[cut:]))
		b[len(b)-1] ^= 1
		require.False(t, s.verify(b[:cut], b[cut:])) // padding belongs to AAD
	}
	u.SetFlags(u.Flags() | wire.SMB2_FLAGS_SERVER_TO_REDIR)
	serverNonce := gmacNonce(u, true)
	serverTag := oracle.Seal(nil, serverNonce[:], nil, unsigned)
	// Direction, command and MID affect the tag; no ASYNC bit is added to nonce for ordinary responses.
	for _, offset := range []int{12, 16, 24, 64, len(packet) - 1} {
		b := append([]byte(nil), unsigned...)
		copy(b[48:64], serverTag)
		b[offset] ^= 1
		require.False(t, s.verify(b))
	}
	u.SetFlags(u.Flags() &^ wire.SMB2_FLAGS_SERVER_TO_REDIR)
	b := append([]byte(nil), unsigned...)
	for i := 48; i < 64; i++ {
		b[i] = 255
	}
	_, err = s.sign(b)
	require.NoError(t, err)
	require.Equal(t, want, b[48:64])
}

func TestGMACScratchBound(t *testing.T) {
	g, err := newGMAC(make([]byte, 16))
	require.NoError(t, err)
	a := make([]byte, 112)
	b := make([]byte, 1<<20)
	_, err = g.sum([12]byte{}, a, b)
	require.NoError(t, err)
	require.GreaterOrEqual(t, cap(g.scratch), len(a)+len(b))
	require.LessOrEqual(t, cap(g.scratch), maxSigningScratch)
	old := &g.scratch[0]
	_, err = g.sum([12]byte{}, a, b)
	require.NoError(t, err)
	require.Same(t, old, &g.scratch[0])
	_, err = g.sum([12]byte{}, a, make([]byte, maxSigningScratch))
	require.NoError(t, err)
	require.Same(t, old, &g.scratch[0])
	_, err = g.sum([12]byte{}, make([]byte, maxDirectTCPSize), a)
	require.Error(t, err)
}

func TestGMACSenderRoleIsNotCallerControlled(t *testing.T) {
	s := &session{conn: &conn{dialect: wire.SMB311, signingAlgorithm: wire.AES128GMAC}}
	require.NoError(t, s.setupKeys(make([]byte, 16)))
	b := make([]byte, 64)
	p := wire.PacketCodec(b)
	p.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetMessageId(7)
	_, err := s.sign(b)
	require.NoError(t, err)
	signature := append([]byte(nil), p.Signature()...)
	clear(p.Signature())
	// A caller-provided direction flag cannot make the client reuse the server nonce.
	n := [12]byte{7}
	tag, err := s.signer.sum(n, b)
	require.NoError(t, err)
	require.Equal(t, tag[:], signature)
}

func TestGMACIndependentTransmitReceive(t *testing.T) {
	s := &session{conn: &conn{dialect: wire.SMB311, signingAlgorithm: wire.AES128GMAC}}
	require.NoError(t, s.setupKeys(make([]byte, 16)))
	key := kdf(make([]byte, 16), []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:], 16)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	oracle, err := cipher.NewGCM(block)
	require.NoError(t, err)
	response := make([]byte, 80+1024)
	p := wire.PacketCodec(response)
	p.SetFlags(wire.SMB2_FLAGS_SIGNED | wire.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetMessageId(7)
	n := gmacNonce(p, true)
	copy(response[48:64], oracle.Seal(nil, n[:], nil, response))
	failures := make(chan error, 2)
	go func() {
		b := make([]byte, 112+1024)
		for i := range 100 {
			wire.PacketCodec(b).SetMessageId(uint64(i))
			if _, e := s.sign(b[:112], b[112:]); e != nil {
				failures <- e
				return
			}
		}
		failures <- nil
	}()
	go func() {
		for range 100 {
			if !s.verify(response[:80], response[80:]) {
				failures <- errors.New("GMAC verification failed")
				return
			}
		}
		failures <- nil
	}()
	require.NoError(t, <-failures)
	require.NoError(t, <-failures)
}

func TestProductionSigningBenchmarkFixture(t *testing.T) {
	for _, algorithm := range []wire.SigningAlgorithm{wire.AES128CMAC, wire.AES128GMAC} {
		for _, read := range []bool{false, true} {
			flat, err := newProductionSigningFixture(algorithm, read, false)
			require.NoError(t, err)
			split, err := newProductionSigningFixture(algorithm, read, true)
			require.NoError(t, err)
			require.Equal(t, flat.packet, split.packet)
			require.Len(t, split.parts, 3)
			require.Len(t, split.parts[2], 16)
			require.Equal(t, 1<<20, len(flat.packet)-len(split.parts[0]))
			p := wire.PacketCodec(split.packet)
			require.False(t, p.IsInvalid())
			if read {
				r := wire.ReadResponseDecoder(p.Body())
				require.False(t, r.IsInvalid())
				require.EqualValues(t, 1<<20, r.DataLength())
				require.True(t, split.session.verify(split.parts...))
			} else {
				r := wire.WriteRequestDecoder(p.Body())
				require.False(t, r.IsInvalid())
				require.EqualValues(t, 1<<20, r.Length())
			}
			if algorithm == wire.AES128GMAC {
				g := split.authenticator()
				require.NotEmpty(t, g.scratch)
				old := &g.scratch[0]
				require.NoError(t, split.run(8, false))
				require.Same(t, old, &g.scratch[0])
				require.NoError(t, split.run(9, true))
			}
		}
	}
}

func TestProductionSigningActualCallFixture(t *testing.T) {
	for _, read := range []bool{false, true} {
		f, err := newProductionSigningFixture(wire.AES128GMAC, read, false)
		require.NoError(t, err)
		f.useActualParts()
		if read {
			require.Len(t, f.parts, 2)
		} else {
			require.Len(t, f.parts, 3)
		}
		require.Nil(t, f.parts[len(f.parts)-1])
		require.NoError(t, f.run(8, false))
		if read {
			require.Empty(t, f.authenticator().scratch)
		} else {
			require.NotEmpty(t, f.authenticator().scratch)
		}
	}
}

type recordingAADAEAD struct {
	cipher.AEAD
	aad   []byte
	calls int
}

func (a *recordingAADAEAD) Seal(dst, nonce, plaintext, aad []byte) []byte {
	a.aad = aad
	a.calls++
	return a.AEAD.Seal(dst, nonce, plaintext, aad)
}

func TestGMACSingleNonemptySegmentUsesOriginalAAD(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	empty := make([]byte, 0)
	for _, tc := range []struct {
		name  string
		parts [][]byte
	}{
		{"only", [][]byte{data}}, {"first", [][]byte{data, nil, empty}},
		{"middle", [][]byte{nil, data, empty}}, {"last", [][]byte{empty, nil, data}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := newGMAC(make([]byte, 16))
			require.NoError(t, err)
			spy := &recordingAADAEAD{AEAD: g.aead}
			g.aead = spy
			g.scratch = bytes.Repeat([]byte{0x7f}, 16)
			scratch := append([]byte(nil), g.scratch...)
			old := &g.scratch[0]
			before := append([]byte(nil), data...)
			nonce := [12]byte{7, 0, 0, 0, 0, 0, 0, 0, 1}
			want := spy.AEAD.Seal(nil, nonce[:], nil, data)
			tag, err := g.sum(nonce, tc.parts...)
			require.NoError(t, err)
			require.Equal(t, want, tag[:])
			require.Equal(t, 1, spy.calls)
			require.Same(t, &data[0], &spy.aad[0], "single nonempty AAD must not be joined")
			require.Equal(t, before, data)
			require.Same(t, old, &g.scratch[0])
			require.Equal(t, scratch, g.scratch)
		})
	}
}

func TestGMACEmptyAndMultipleSegmentsPreserveTagsAndScratch(t *testing.T) {
	for _, parts := range [][][]byte{nil, {nil}, {[]byte{}}, {nil, []byte{}, nil}} {
		g, err := newGMAC(make([]byte, 16))
		require.NoError(t, err)
		g.scratch = bytes.Repeat([]byte{0x7f}, 16)
		before := append([]byte(nil), g.scratch...)
		old := &g.scratch[0]
		tag, err := g.sum([12]byte{}, parts...)
		require.NoError(t, err)
		require.Equal(t, "58e2fccefa7e3061367f1d57a4e7455a", hex.EncodeToString(tag[:]))
		require.Equal(t, before, g.scratch)
		require.Same(t, old, &g.scratch[0])
	}
	g, err := newGMAC(make([]byte, 16))
	require.NoError(t, err)
	spy := &recordingAADAEAD{AEAD: g.aead}
	g.aead = spy
	first, second := []byte{1, 2}, []byte{3, 4, 5}
	g.scratch = make([]byte, 32)
	old := &g.scratch[0]
	joined := append(append([]byte(nil), first...), second...)
	nonce := [12]byte{7}
	want := spy.AEAD.Seal(nil, nonce[:], nil, joined)
	tag, err := g.sum(nonce, nil, first, []byte{}, second, nil)
	require.NoError(t, err)
	require.Equal(t, want, tag[:])
	require.Equal(t, joined, spy.aad)
	require.Same(t, old, &spy.aad[0])
	require.Same(t, old, &g.scratch[0])
	require.Equal(t, []byte{1, 2}, first)
	require.Equal(t, []byte{3, 4, 5}, second)
	// An existing large scratch remains retained but is not touched by this fast path.
	g.scratch = make([]byte, maxSigningScratch)
	old = &g.scratch[0]
	_, err = g.sum(nonce, nil, first, nil)
	require.NoError(t, err)
	require.Same(t, old, &g.scratch[0])
	require.Len(t, g.scratch, maxSigningScratch)
}

func TestGMACFastPathStillChecksEntireTransportLength(t *testing.T) {
	boundary := make([]byte, maxDirectTCPSize+1)
	for _, tc := range []struct {
		name    string
		parts   [][]byte
		invalid bool
	}{
		{"exact single", [][]byte{nil, boundary[:maxDirectTCPSize], nil}, false},
		{"oversize single", [][]byte{nil, boundary, nil}, true},
		{"exact multiple", [][]byte{boundary[:maxDirectTCPSize-1], nil, []byte{0}}, false},
		{"oversize later segment", [][]byte{boundary[:maxDirectTCPSize], nil, []byte{0}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := newGMAC(make([]byte, 16))
			require.NoError(t, err)
			spy := &recordingAADAEAD{AEAD: g.aead}
			g.aead = spy
			g.scratch = make([]byte, 8)
			old := &g.scratch[0]
			_, err = g.sum([12]byte{}, tc.parts...)
			if tc.invalid {
				require.Error(t, err)
				require.Zero(t, spy.calls)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, spy.calls)
				require.Len(t, spy.aad, maxDirectTCPSize)
			}
			require.Same(t, old, &g.scratch[0])
			require.Len(t, g.scratch, 8, "transport-size temporary or fast AAD must not grow retained scratch")
		})
	}
}
