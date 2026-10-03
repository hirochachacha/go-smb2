package directory

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func TestIsGlobIOError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"EOF", &protocol.TransportError{Err: io.EOF}, true},
		{"short read", &protocol.TransportError{Err: io.ErrUnexpectedEOF}, true},
		{"closed", &protocol.TransportError{Err: net.ErrClosed}, true},
		{"network", &protocol.TransportError{Err: &net.OpError{Op: "read", Net: "tcp", Err: io.EOF}}, true},
		{"wrapped", &os.PathError{Op: "glob", Path: ".", Err: &protocol.TransportError{Err: io.EOF}}, true},
		{"canceled", &protocol.TransportError{Err: context.Canceled}, false},
		{"deadline", &protocol.TransportError{Err: context.DeadlineExceeded}, false},
		{"joined cancellation", errors.Join(context.Canceled, &protocol.TransportError{Err: io.EOF}), false},
		{"framing", &protocol.TransportError{Err: errors.New("invalid transport format")}, false},
		{"invalid response", &protocol.InvalidResponseError{Message: "bad directory entry"}, false},
		{"dot-only", errors.New("query directory returned only dot entries"), false},
		{"permission", os.ErrPermission, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsGlobIOError(tc.err); got != tc.want {
				t.Fatalf("IsGlobIOError(%v)=%t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

func TestReaderNilReceiver(t *testing.T) {
	var r *Reader
	if err := r.Close(); err != nil {
		t.Fatalf("r.Close() = %v, want nil", err)
	}
	ctx := context.Background()
	if _, err := r.Names(ctx, "*"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("r.Names() = %v, want os.ErrInvalid", err)
	}
}

func TestOpenAndReadPageNilArguments(t *testing.T) {
	ctx := context.Background()
	var nilCtx context.Context

	if _, err := Open(ctx, nil, "dir"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("Open(nil) = %v, want os.ErrInvalid", err)
	}
	if _, err := ReadPage[string](ctx, nil, wire.FileId{}, "*", func(d wire.FileIdBothDirectoryInformationDecoder) string { return "" }); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("ReadPage(nil request) = %v, want os.ErrInvalid", err)
	}
	if _, err := ReadPage[string](ctx, func() *protocol.Request { return nil }, wire.FileId{}, "*", nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("ReadPage(nil decode) = %v, want os.ErrInvalid", err)
	}

	// Nil context panics
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for Open(nil context)")
			}
		}()
		_, _ = Open(nilCtx, nil, "dir")
	}()

	var r *Reader
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for Reader.Names(nil context)")
			}
		}()
		_, _ = r.Names(nilCtx, "*")
	}()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for ReadPage(nil context)")
			}
		}()
		_, _ = ReadPage[string](nilCtx, nil, wire.FileId{}, "*", nil)
	}()

	// Uninitialized reader
	var uninitReader Reader
	if err := uninitReader.Close(); err != nil {
		t.Fatalf("uninitReader.Close() = %v, want nil", err)
	}
	if _, err := uninitReader.Names(ctx, "*"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("uninitReader.Names() = %v, want os.ErrInvalid", err)
	}
}
