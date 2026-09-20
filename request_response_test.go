package smb2

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func serveFileResponse(t *testing.T, peer net.Conn, response wire.Packet, status erref.NtStatus) {
	t.Helper()
	request, err := readMsg(peer)
	if err != nil {
		t.Errorf("read request: %v", err)
		return
	}
	if err := testWriteResponse(peer, request, response, status, wire.PacketCodec(request).SessionId(), wire.PacketCodec(request).TreeId()); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func TestIoctlBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	want := []byte("partial output data from buffer overflow")
	go serveFileResponse(t, peer, &wire.IoctlResponse{
		CtlCode: wire.FSCTL_PIPE_TRANSCEIVE,
		Output:  rawEncoder(want),
	}, erref.STATUS_BUFFER_OVERFLOW)

	got, err := fs.ioctl(context.Background(), &wire.FileId{}, &wire.IoctlRequest{
		CtlCode:           wire.FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 1024,
	})
	if !errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) {
		t.Fatalf("ioctl error = %v, want STATUS_BUFFER_OVERFLOW", err)
	}
	if string(got) != string(want) {
		t.Fatalf("ioctl output = %q, want %q", got, want)
	}
}

func TestIoctlErrorReleasesBuffer(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	go serveFileResponse(t, peer, &wire.ErrorResponse{CommandCode: wire.SMB2_IOCTL}, erref.STATUS_ACCESS_DENIED)

	got, err := fs.ioctl(context.Background(), &wire.FileId{}, &wire.IoctlRequest{
		CtlCode:           wire.FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 1024,
	})
	if !errors.Is(err, erref.STATUS_ACCESS_DENIED) || got != nil {
		t.Fatalf("ioctl result = (%q, %v), want nil and ACCESS_DENIED", got, err)
	}
}

func TestReadBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	want := []byte("partial read data from buffer overflow")
	go serveFileResponse(t, peer, &wire.ReadResponse{Data: want, DataRemaining: 100}, erref.STATUS_BUFFER_OVERFLOW)

	buf := make([]byte, 1024)
	n, err := fs.readAtChunk(context.Background(), &wire.FileId{}, buf, 0)
	if !errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) || n != len(want) || string(buf[:n]) != string(want) {
		t.Fatalf("read result = (%d, %v, %q), want partial overflow", n, err, buf[:n])
	}
}

func TestReadBufferOverflowInReadMethodReturnsSuccess(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	want := []byte("pipe chunk data")
	go serveFileResponse(t, peer, &wire.ReadResponse{Data: want, DataRemaining: 50}, erref.STATUS_BUFFER_OVERFLOW)

	buf := make([]byte, 1024)
	n, err := fs.read(context.Background(), &wire.FileId{}, buf, 0)
	if err != nil || n != len(want) || string(buf[:n]) != string(want) {
		t.Fatalf("read result = (%d, %v, %q), want successful partial read", n, err, buf[:n])
	}
}

func TestReadErrorReleasesBuffer(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	go serveFileResponse(t, peer, &wire.ErrorResponse{CommandCode: wire.SMB2_READ}, erref.STATUS_ACCESS_DENIED)

	buf := make([]byte, 1024)
	n, err := fs.readAtChunk(context.Background(), &wire.FileId{}, buf, 0)
	if !errors.Is(err, erref.STATUS_ACCESS_DENIED) || n != 0 {
		t.Fatalf("read result = (%d, %v), want zero and ACCESS_DENIED", n, err)
	}
}

func TestQueryInfoBufferOverflowReturnsPartialDataAndReleasesBuffer(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	want := []byte("partial query info output data")
	go serveFileResponse(t, peer, &wire.QueryInfoResponse{Output: rawEncoder(want)}, erref.STATUS_BUFFER_OVERFLOW)

	res, err := fs.Request().WithFileID(&wire.FileId{}).
		QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 1024).
		Do(context.Background())
	if !errors.Is(err, erref.STATUS_BUFFER_OVERFLOW) {
		t.Fatalf("query info error = %v, want STATUS_BUFFER_OVERFLOW", err)
	}
	if got, ok := protocol.BufferOverflowData(err); !ok || string(got) != string(want) {
		t.Fatalf("query info overflow data = (%q, %v), want %q", got, ok, want)
	}
	if res != nil {
		res.Close()
	}
}

func TestQueryInfoErrorReleasesBuffer(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	go serveFileResponse(t, peer, &wire.ErrorResponse{CommandCode: wire.SMB2_QUERY_INFO}, erref.STATUS_ACCESS_DENIED)

	res, err := fs.Request().WithFileID(&wire.FileId{}).
		QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 1024).
		Do(context.Background())
	if !errors.Is(err, erref.STATUS_ACCESS_DENIED) || res != nil {
		t.Fatalf("query info result = (%v, %v), want nil and ACCESS_DENIED", res, err)
	}
}

func TestReadValidatesBeforeWritingCallerBuffer(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	want := []byte("response exceeds caller buffer")
	go serveFileResponse(t, peer, &wire.ReadResponse{Data: want}, erref.STATUS_SUCCESS)

	buf := make([]byte, 8)
	for i := range buf {
		buf[i] = 0xa5
	}
	_, err := fs.readAtChunk(context.Background(), &wire.FileId{}, buf, 0)
	var invalid *protocol.InvalidResponseError
	if !errors.As(err, &invalid) || !bytes.Equal(buf, bytes.Repeat([]byte{0xa5}, len(buf))) {
		t.Fatalf("read validation result = (%v, %x), want InvalidResponseError and untouched buffer", err, buf)
	}
}

func TestDirectReadBoundsResponseToRequestedLength(t *testing.T) {
	fs, peer := newProtocolTestShare(t)
	go serveFileResponse(t, peer, &wire.ReadResponse{Data: make([]byte, 16)}, erref.STATUS_SUCCESS)

	buf := make([]byte, 8)
	_, err := fs.readAtChunk(context.Background(), &wire.FileId{}, buf, 0)
	var invalid *protocol.InvalidResponseError
	if !errors.As(err, &invalid) || !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatalf("overlong read result = (%v, %x), want InvalidResponseError and untouched buffer", err, buf)
	}
}

func TestSessionServername(t *testing.T) {
	for _, test := range []struct {
		addr, want string
	}{
		{"192.0.2.10:445", "192.0.2.10"},
		{"[2001:db8::10]:445", "2001:db8::10"},
		{"server", "server"},
	} {
		t.Run(test.addr, func(t *testing.T) {
			s := &Session{addr: test.addr}
			if got := s.serverName(); got != test.want {
				t.Fatalf("serverName = %q, want %q", got, test.want)
			}
		})
	}
}
