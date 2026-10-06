package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// CPU-only fixtures: payload and packet are allocated/encoded before timing.
// Three segments share the preallocated packet backing array: fixed header,
// payload except its last 16 bytes, and that non-empty 16-byte tail. This keeps
// exactly the same valid wire message as contiguous, without transport framing.
// Real direct WRITE may have an empty final padding segment; direct READ uses
// two segments. The three-segment fixture isolates the production joining path.
type productionSigningFixture struct {
	session *session
	packet  []byte
	parts   [][]byte
	read    bool
}

func newProductionSigningFixture(algorithm wire.SigningAlgorithm, read, split bool) (*productionSigningFixture, error) {
	s := &session{conn: &conn{dialect: wire.SMB311, signingAlgorithm: algorithm}}
	key := make([]byte, 16) // Synthetic key only; no credentials or SMB connections.
	if err := s.setupKeys(key); err != nil {
		return nil, err
	}
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	var encoder wire.Packet
	fixed := 112
	if read {
		encoder = &wire.ReadResponse{Data: payload}
		fixed = 80
		encoder.SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR | wire.SMB2_FLAGS_SIGNED)
	} else {
		encoder = &wire.WriteRequest{Data: payload}
	}
	encoder.SetMessageId(7)
	packet := make([]byte, encoder.Size())
	encoder.Encode(packet)
	f := &productionSigningFixture{session: s, packet: packet, parts: [][]byte{packet}, read: read}
	if split {
		f.parts = [][]byte{packet[:fixed], packet[fixed : len(packet)-16], packet[len(packet)-16:]}
	}
	if read {
		p := wire.PacketCodec(packet)
		if algorithm == wire.AES128GMAC {
			block, err := aes.NewCipher(kdf(key, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:], 16))
			if err != nil {
				return nil, err
			}
			g, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			nonce := [12]byte{7, 0, 0, 0, 0, 0, 0, 0, 1}
			p.SetSignature(g.Seal(nil, nonce[:], nil, packet))
		} else {
			s.verifier.Reset()
			s.verifier.Write(packet)
			p.SetSignature(s.verifier.Sum(nil))
		}
	}
	// Validate and warm the production operation, excluding this from timing.
	if err := f.run(7, false); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *productionSigningFixture) authenticator() *gmac {
	if f.read {
		g, _ := f.session.gmacVerifier.(*gmac)
		return g
	}
	g, _ := f.session.gmacSigner.(*gmac)
	return g
}

func (f *productionSigningFixture) run(mid uint64, cold bool) error {
	// Cold means scratch=nil each iteration, not cold CPU cache or key setup.
	if cold {
		f.authenticator().scratch = nil
	}
	if f.read {
		// Repeat verification of the same valid MID/tag. Receiver re-verification
		// needs no nonce consumption map; no signing/setup is hidden in this timer.
		if !f.session.verify(f.parts...) {
			return errors.New("benchmark signature verification failed")
		}
		return nil
	}
	wire.PacketCodec(f.packet).SetMessageId(mid) // Fresh outgoing nonce per operation.
	_, err := f.session.sign(f.parts...)
	return err
}

func BenchmarkProductionSigning(b *testing.B) {
	for _, algorithm := range []struct {
		name string
		id   wire.SigningAlgorithm
	}{{"CMAC", wire.AES128CMAC}, {"GMAC", wire.AES128GMAC}} {
		for _, operation := range []struct {
			name string
			read bool
		}{{"WRITE-sign", false}, {"READ-verify", true}} {
			for _, layout := range []struct {
				name  string
				split bool
			}{{"contiguous", false}, {"three-segment", true}} {
				modes := []string{"warm"}
				if algorithm.id == wire.AES128GMAC && layout.split {
					modes = append(modes, "cold")
				}
				for _, mode := range modes {
					b.Run(algorithm.name+"/"+operation.name+"/"+layout.name+"/"+mode, func(b *testing.B) {
						f, err := newProductionSigningFixture(algorithm.id, operation.read, layout.split)
						if err != nil {
							b.Fatal(err)
						}
						b.SetBytes(1 << 20) // Payload throughput, excluding the 112/80-byte header.
						b.ReportAllocs()
						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							if err := f.run(uint64(i)+8, mode == "cold"); err != nil {
								b.Fatal(err)
							}
						}
						b.StopTimer()
					})
				}
			}
		}
	}
}

// These shapes match conn.makeOutstandingRequest's direct WRITE (no padding)
// and conn.tryVerify's buffered READ with nil ext. A nil argument still triggers
// the current GMAC join path because it branches on len(pkts), not nonempty parts.
func (f *productionSigningFixture) useActualParts() {
	if f.read {
		f.parts = [][]byte{f.packet, nil}
	} else {
		f.parts = [][]byte{f.packet[:112], f.packet[112:], nil}
	}
}

func BenchmarkProductionSigningActualCalls(b *testing.B) {
	for _, algorithm := range []struct {
		name string
		id   wire.SigningAlgorithm
	}{{"CMAC", wire.AES128CMAC}, {"GMAC", wire.AES128GMAC}} {
		for _, operation := range []struct {
			name string
			read bool
		}{{"WRITE-direct", false}, {"READ-buffered-nil-ext", true}} {
			modes := []string{"warm"}
			if algorithm.id == wire.AES128GMAC {
				modes = append(modes, "cold")
			}
			for _, mode := range modes {
				b.Run(algorithm.name+"/"+operation.name+"/"+mode, func(b *testing.B) {
					f, err := newProductionSigningFixture(algorithm.id, operation.read, false)
					if err != nil {
						b.Fatal(err)
					}
					f.useActualParts()
					if err = f.run(7, false); err != nil {
						b.Fatal(err)
					}
					b.SetBytes(1 << 20)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if err = f.run(uint64(i)+8, mode == "cold"); err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
				})
			}
		}
	}
}
