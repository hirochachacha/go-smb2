package smb2

import (
	"encoding/binary"
	"strconv"
	"testing"
)

// The QUERY_DIRECTORY decoders validate a server-supplied length before
// slicing by it. That validation overflows.
//
// IsInvalid computed 64+FileNameLength in uint32, so a FileNameLength
// near the top of the range wrapped the sum to a small number, the
// comparison passed, and the decoder went on to slice a buffer by a
// length it had just failed to reject.
//
// A directory listing against a hostile or man-in-the-middle SMB server
// crashes the process on it. GO-2026-5051.
func TestFileDirectoryInformationDecoderRejectsOverflowingNameLength(t *testing.T) {
	for _, nameLen := range []uint32{
		0xFFFFFFFF, // 64 + this wraps to 63
		0xFFFFFFC0, // wraps to exactly 0
		0xFFFFFFC1, // wraps to 1
		1 << 31,
		0x7FFFFFFF,
	} {
		// A minimal entry: the 64-byte fixed part and no name, claiming
		// a name far larger than the buffer.
		buf := make([]byte, 64)
		binary.LittleEndian.PutUint32(buf[60:64], nameLen)

		d := FileDirectoryInformationDecoder(buf)
		if !d.IsInvalid() {
			t.Errorf("FileNameLength %#x in a %d-byte buffer was accepted as valid",
				nameLen, len(buf))
		}
	}
}

// A well-formed entry must still be accepted — the bound must reject
// what does not fit, not everything.
func TestFileDirectoryInformationDecoderAcceptsAWellFormedEntry(t *testing.T) {
	const name = 8
	buf := make([]byte, 64+name)
	binary.LittleEndian.PutUint32(buf[60:64], name)

	if d := FileDirectoryInformationDecoder(buf); d.IsInvalid() {
		t.Errorf("a %d-byte buffer with a %d-byte name was rejected", len(buf), name)
	}

	// One byte short of what it claims must still be rejected.
	short := make([]byte, 64+name-1)
	binary.LittleEndian.PutUint32(short[60:64], name)
	if d := FileDirectoryInformationDecoder(short); !d.IsInvalid() {
		t.Errorf("a buffer one byte short of its declared name was accepted")
	}
}

func TestFileDirectoryInformationDecoderRejectsTruncatedFixedPart(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{name: "nil"},
	}
	for length := 0; length < 64; length++ {
		testCases = append(testCases, struct {
			name  string
			input []byte
		}{name: strconv.Itoa(length), input: make([]byte, length)})
	}
	backing := make([]byte, 64)
	testCases = append(testCases, struct {
		name  string
		input []byte
	}{name: "spare-capacity", input: backing[:63]})

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncated directory information caused panic: %v", r)
				}
			}()

			if d := FileDirectoryInformationDecoder(testCase.input); !d.IsInvalid() {
				t.Fatalf("%d-byte directory information was accepted", len(testCase.input))
			}
		})
	}
}

// The same arithmetic appears in three other decoders, all reachable
// from a server response.
func TestOtherDecodersRejectOverflowingLengths(t *testing.T) {
	t.Run("SrvRequestResumeKeyResponse", func(t *testing.T) {
		buf := make([]byte, 28)
		binary.LittleEndian.PutUint32(buf[24:28], 0xFFFFFFFF)
		if d := SrvRequestResumeKeyResponseDecoder(buf); !d.IsInvalid() {
			t.Error("an overflowing ContextLength was accepted")
		}
	})

	t.Run("FileQuotaInformation", func(t *testing.T) {
		buf := make([]byte, 40)
		binary.LittleEndian.PutUint32(buf[4:8], 0xFFFFFFFF)
		if d := FileQuotaInformationDecoder(buf); !d.IsInvalid() {
			t.Error("an overflowing SidLength was accepted")
		}
	})
}

func TestFileQuotaInformationDecoderRejectsTruncatedFixedPart(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{name: "nil"},
	}
	for length := 0; length < 40; length++ {
		testCases = append(testCases, struct {
			name  string
			input []byte
		}{name: strconv.Itoa(length), input: make([]byte, length)})
	}
	backing := make([]byte, 40)
	testCases = append(testCases, struct {
		name  string
		input []byte
	}{name: "spare-capacity", input: backing[:39]})

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncated quota information caused panic: %v", r)
				}
			}()

			if d := FileQuotaInformationDecoder(testCase.input); !d.IsInvalid() {
				t.Fatalf("%d-byte quota information was accepted", len(testCase.input))
			}
		})
	}
}

func TestSrvRequestResumeKeyResponseRejectsTruncatedResponse(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("truncated response caused panic: %v", r)
		}
	}()

	if !SrvRequestResumeKeyResponseDecoder(nil).IsInvalid() {
		t.Fatal("truncated response was accepted")
	}
}

func TestFileFsFullSizeInformationDecoderValidatesAllocationUnits(t *testing.T) {
	testCases := []struct {
		name   string
		offset int
	}{
		{name: "TotalAllocationUnits", offset: 0},
		{name: "CallerAvailableAllocationUnits", offset: 8},
		{name: "ActualAvailableAllocationUnits", offset: 16},
	}
	values := []struct {
		name    string
		value   int64
		invalid bool
	}{
		{name: "negative one", value: -1, invalid: true},
		{name: "minimum int64", value: -1 << 63, invalid: true},
		{name: "zero", value: 0},
		{name: "one", value: 1},
		{name: "maximum int64", value: 1<<63 - 1},
	}

	for _, testCase := range testCases {
		for _, value := range values {
			t.Run(testCase.name+"/"+value.name, func(t *testing.T) {
				buf := make([]byte, 32)
				binary.LittleEndian.PutUint64(buf[testCase.offset:testCase.offset+8], uint64(value.value))

				if got := FileFsFullSizeInformationDecoder(buf).IsInvalid(); got != value.invalid {
					t.Errorf("IsInvalid() = %v for %d in %s, want %v", got, value.value, testCase.name, value.invalid)
				}
			})
		}
	}
}

func TestFileFsFullSizeInformationDecoderRejectsTruncatedBody(t *testing.T) {
	for length := 0; length < 32; length++ {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncated full size information caused panic: %v", r)
				}
			}()

			if !FileFsFullSizeInformationDecoder(make([]byte, length)).IsInvalid() {
				t.Fatalf("%d-byte full size information was accepted", length)
			}
		})
	}
}
