package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// Keep a normal 1 MiB payload plus SMB headers/padding in reusable storage.
// Larger frames are supported but their scratch is not retained by the session.
const maxSigningScratch = (1 << 20) + (64 << 10)

// packetSigner computes the signature of one message given as contiguous
// segments. It is not safe for concurrent use.
type packetSigner interface {
	sum(nonce [12]byte, pkts ...[]byte) ([16]byte, error)
	// usesNonce reports whether the signature depends on the nonce derived
	// from the message ID, so a signed message ID must never be reused.
	usesNonce() bool
}

// hashSigner signs with HMAC-SHA256 or AES-CMAC, which ignore the nonce.
type hashSigner struct {
	h      hash.Hash
	digest [sha256.Size]byte
}

func newHashSigner(h hash.Hash) *hashSigner { return &hashSigner{h: h} }

func (s *hashSigner) sum(_ [12]byte, pkts ...[]byte) (tag [16]byte, err error) {
	s.h.Reset()
	for _, pkt := range pkts {
		if len(pkt) > 0 {
			s.h.Write(pkt)
		}
	}
	copy(tag[:], s.h.Sum(s.digest[:0]))
	return tag, nil
}

func (*hashSigner) usesNonce() bool { return false }

type gmac struct {
	aead    cipher.AEAD
	scratch []byte
}

func newGMAC(key []byte) (*gmac, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("protocol: initialize GMAC cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("protocol: initialize GMAC: %w", err)
	}
	return &gmac{aead: aead}, nil
}

func (*gmac) usesNonce() bool { return true }

// gmacNonce uses sender direction and CANCEL command, never the ASYNC flag
// ([MS-SMB2] 3.1.4.1). The first packet segment has a validated SMB2 header.
func gmacNonce(p wire.PacketCodec, fromServer bool) (nonce [12]byte) {
	binary.LittleEndian.PutUint64(nonce[:8], p.MessageId())
	var flags uint32
	if fromServer {
		flags = 1
	}
	if p.Command() == wire.SMB2_CANCEL {
		flags |= 2
	}
	binary.LittleEndian.PutUint32(nonce[8:], flags)
	return
}

func (g *gmac) sum(nonce [12]byte, pkts ...[]byte) (tag [16]byte, err error) {
	total := 0
	nonempty := 0
	var aad []byte
	for _, pkt := range pkts {
		if len(pkt) > maxDirectTCPSize-total {
			return tag, errors.New("protocol: signing message exceeds transport size")
		}
		total += len(pkt)
		if len(pkt) != 0 {
			nonempty++
			aad = pkt
		}
	}
	// Empty arguments do not require joining a single real AAD segment.
	if nonempty > 1 {
		if total <= maxSigningScratch {
			if cap(g.scratch) < total {
				g.scratch = make([]byte, total)
			}
			aad = g.scratch[:total]
		} else {
			// Larger messages borrow a pooled receive buffer rather than
			// keeping a per-session scratch of the maximum message size.
			buf := allocRecvBuf(total)
			defer releaseRecvBuf(buf)
			aad = buf.data[:total]
		}
		off := 0
		for _, pkt := range pkts {
			off += copy(aad[off:], pkt)
		}
	}
	// GMAC is GCM with no plaintext and the whole signed message as AAD.
	g.aead.Seal(tag[:0], nonce[:], nil, aad)
	return tag, nil
}
