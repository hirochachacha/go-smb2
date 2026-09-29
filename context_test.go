package smb2_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/client"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/user"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/stretchr/testify/require"
)

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
		&dfs.Client{}, &user.Client{},
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
		{"user.NewClient", user.NewClient},
		{"protocol.DialQUICTransport", protocol.DialQUICTransport},
	} {
		t.Run(function.name, func(t *testing.T) {
			check(t, reflect.ValueOf(function.call))
		})
	}
}
