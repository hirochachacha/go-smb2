package smb2

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
)

// Keep this helper available to future lower/upper wire tests. V3 referral
// strings are UTF-16 and offsets are relative to the referral entry.
func makeDFSReferralV3(prefix, target string) []byte {
	path := append(utf16le.EncodeStringToBytes(prefix), 0, 0)
	network := append(utf16le.EncodeStringToBytes(target), 0, 0)
	const entrySize = 34
	b := make([]byte, 8+entrySize+len(path)+len(path)+len(network))
	le := binary.LittleEndian
	le.PutUint16(b[:2], uint16(utf16le.EncodedStringLen(prefix)))
	le.PutUint16(b[2:4], 1)
	le.PutUint16(b[8:10], 3)
	le.PutUint16(b[10:12], entrySize)
	le.PutUint32(b[16:20], 300)
	le.PutUint16(b[20:22], entrySize)
	le.PutUint16(b[22:24], entrySize+uint16(len(path)))
	le.PutUint16(b[24:26], entrySize+uint16(len(path)*2))
	copy(b[8+entrySize:], path)
	copy(b[8+entrySize+len(path):], path)
	copy(b[8+entrySize+len(path)*2:], network)
	return b
}

func TestValidReferralPathForms(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"",
		`\dc-one`,
		`\\dc-two`,
		`\\server\share`,
		`\\server\share\root\link`,
	} {
		t.Run(path, func(t *testing.T) {
			if !pathpkg.ValidReferralPath(path) {
				t.Fatalf("pathpkg.ValidReferralPath(%q) = false", path)
			}
		})
	}
}

func TestGetDFSReferralsRejectsUndocumentedPathFormsBeforeSessionUse(t *testing.T) {
	t.Parallel()
	var session *Session
	for _, path := range []string{
		`domain`,
		`server\share`,
		`\server\share`,
		`\\server\`,
		`\\\server\share`,
		`\\server\\share`,
	} {
		t.Run(path, func(t *testing.T) {
			if pathpkg.ValidReferralPath(path) {
				t.Fatalf("pathpkg.ValidReferralPath(%q) accepted undocumented path form", path)
			}
			_, publicErr := session.GetDFSReferrals(context.Background(), path)
			if !errors.Is(publicErr, os.ErrInvalid) {
				t.Fatalf("GetDFSReferrals(%q) error = %v, want os.ErrInvalid", path, publicErr)
			}
			if errors.Is(publicErr, net.ErrClosed) {
				t.Fatalf("GetDFSReferrals(%q) reached session use: %v", path, publicErr)
			}
		})
	}
}
