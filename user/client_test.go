package user

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/client"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

type interruptedPipe struct {
	calls    int
	closed   bool
	closeCtx error
}

func (p *interruptedPipe) Call(context.Context, func(uint32) (wire.Encoder, error)) ([]byte, uint32, error) {
	p.calls++
	return nil, 1, nil
}

func (p *interruptedPipe) ReadAtLeast(ctx context.Context, _ []byte, _ int) (int, error) {
	return 0, ctx.Err()
}

func (p *interruptedPipe) Close(ctx context.Context) error {
	p.closed = true
	p.closeCtx = ctx.Err()
	return nil
}

func TestInterruptedRPCResponseInvalidatesPipe(t *testing.T) {
	t.Parallel()
	pipe := &interruptedPipe{}
	c := &Client{pipe: pipe, turn: make(chan struct{}, 1)}
	c.turn <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.callLocked(ctx, 1, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("callLocked = %v, want canceled", err)
	}
	if !pipe.closed || pipe.closeCtx != nil {
		t.Fatal("interrupted pipe was not closed with a live cleanup context")
	}
	if _, err := c.Lookup(context.Background(), "user"); !errors.Is(err, errClientClosed) {
		t.Fatalf("later Lookup = %v, want closed", err)
	}
	if pipe.calls != 1 {
		t.Fatalf("pipe calls = %d, want 1", pipe.calls)
	}
}

func TestCloseWithCanceledContextReleasesPipe(t *testing.T) {
	t.Parallel()
	pipe := &interruptedPipe{}
	c := &Client{pipe: pipe, turn: make(chan struct{}, 1)}
	c.turn <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close with canceled context = %v", err)
	}
	if !pipe.closed || pipe.closeCtx != nil {
		t.Fatal("Close did not release the pipe with a live cleanup context")
	}
}

func TestUserClientNilArguments(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var nilCtx context.Context

	// NewClient nil context panics
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in NewClient")
			}
		}()
		_, _ = NewClient(nilCtx, nil)
	}()

	// A nil share is a user client argument error.
	if _, err := NewClient(ctx, nil); err == nil || errors.Is(err, os.ErrInvalid) {
		t.Fatalf("NewClient(ctx, nil) = %v, want user error", err)
	}

	var nilClient *Client
	// Nil receiver Current
	if _, err := nilClient.Current(ctx); !errors.Is(err, errInvalidClient) {
		t.Fatalf("nilClient.Current = %v, want errInvalidClient", err)
	}

	// Nil receiver Lookup
	if _, err := nilClient.Lookup(ctx, ""); !errors.Is(err, errInvalidArgument) {
		t.Fatalf("nilClient.Lookup(empty) = %v, want errInvalidArgument", err)
	}
	if _, err := nilClient.Lookup(ctx, "user"); !errors.Is(err, errInvalidClient) {
		t.Fatalf("nilClient.Lookup = %v, want errInvalidClient", err)
	}

	// Nil receiver LookupSID
	if _, err := nilClient.LookupSID(ctx, nil); !errors.Is(err, errInvalidArgument) {
		t.Fatalf("nilClient.LookupSID(nil) = %v, want errInvalidArgument", err)
	}
	sid := &security.SID{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{21}}
	if _, err := nilClient.LookupSID(ctx, sid); !errors.Is(err, errInvalidClient) {
		t.Fatalf("nilClient.LookupSID = %v, want errInvalidClient", err)
	}

	// Nil receiver Close
	if err := nilClient.Close(ctx); !errors.Is(err, errInvalidClient) {
		t.Fatalf("nilClient.Close = %v, want errInvalidClient", err)
	}

	// Nil context panics on Client methods
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in Current")
			}
		}()
		_, _ = nilClient.Current(nilCtx)
	}()
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in Lookup")
			}
		}()
		_, _ = nilClient.Lookup(nilCtx, "user")
	}()
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in LookupSID")
			}
		}()
		_, _ = nilClient.LookupSID(nilCtx, sid)
	}()
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context in Close")
			}
		}()
		_ = nilClient.Close(nilCtx)
	}()
}

func TestUserClientClosedAndCanceled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Closed client returns a user package error.
	c := &Client{
		closed: true,
		turn:   make(chan struct{}, 1),
	}
	c.turn <- struct{}{}

	if _, err := c.Current(ctx); !errors.Is(err, errClientClosed) {
		t.Fatalf("closed Current = %v, want errClientClosed", err)
	}
	if _, err := c.Lookup(ctx, "user"); !errors.Is(err, errClientClosed) {
		t.Fatalf("closed Lookup = %v, want errClientClosed", err)
	}
	sid := &security.SID{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{21}}
	if _, err := c.LookupSID(ctx, sid); !errors.Is(err, errClientClosed) {
		t.Fatalf("closed LookupSID = %v, want errClientClosed", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("closed Close = %v, want nil", err)
	}

	// Canceled context on lock
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.lock(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("lock with canceled context = %v, want context.Canceled", err)
	}

	// Lock with nil receiver or uninitialized turn
	var uninitClient Client
	if err := uninitClient.lock(ctx); !errors.Is(err, errInvalidClient) {
		t.Fatalf("uninitClient.lock = %v, want errInvalidClient", err)
	}
}

func TestPublicAPIsRejectNilContext(t *testing.T) {
	contextType := reflect.TypeFor[context.Context]()
	check := func(t *testing.T, call reflect.Value) {
		t.Helper()
		args := make([]reflect.Value, call.Type().NumIn())
		for i := range args {
			args[i] = reflect.Zero(call.Type().In(i))
		}
		require.PanicsWithValue(t, "nil context", func() {
			if call.Type().IsVariadic() {
				call.CallSlice(args)
			} else {
				call.Call(args)
			}
		})
	}

	// Register types; reflection discovers their exported context methods.
	for _, receiver := range []any{
		&smb2.Dialer{}, &smb2.Session{}, &smb2.Share{}, &smb2.File{},
		smb2.TCPDialer{}, smb2.QUICDialer{},
		&client.Client{}, &client.File{},
		auth.NTLMCredential{}, &auth.KerberosCredential{},
		&dfs.Client{}, &Client{},
		&protocol.Dialer{}, &protocol.Session{}, &protocol.Tree{}, &protocol.Request{},
	} {
		typ := reflect.TypeOf(receiver)
		for i := range typ.NumMethod() {
			method := typ.Method(i)
			if method.Type.NumIn() < 2 || method.Type.In(1) != contextType {
				continue
			}
			t.Run(typ.String()+"."+method.Name, func(t *testing.T) {
				t.Run("zero receiver", func(t *testing.T) {
					value := reflect.Zero(typ)
					if typ.Kind() == reflect.Pointer {
						value = reflect.New(typ.Elem())
					}
					check(t, value.Method(i))
				})
				if typ.Kind() == reflect.Pointer {
					t.Run("nil receiver", func(t *testing.T) {
						check(t, reflect.Zero(typ).Method(i))
					})
				}
			})
		}
	}

	// Package functions cannot be enumerated through reflection.
	for _, function := range []struct {
		name string
		call any
	}{
		{"user.NewClient", NewClient},
		{"protocol.DialQUICTransport", protocol.DialQUICTransport},
	} {
		t.Run(function.name, func(t *testing.T) {
			check(t, reflect.ValueOf(function.call))
		})
	}
}
