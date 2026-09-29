package protocol

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDialerInvalidArgumentsPanic(t *testing.T) {
	for _, name := range []string{"nil Dialer", "nil Initiator", "nil Transport"} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			d := &Dialer{}
			var initiator Initiator = &singleRoundInitiator{}
			transport := NewTransport(client)
			switch name {
			case "nil Dialer":
				d = nil
			case "nil Initiator":
				initiator = nil
			case "nil Transport":
				transport = nil
			}
			require.PanicsWithValue(t, "protocol: "+name, func() {
				_, _ = d.Dial(context.Background(), initiator, transport)
			})
			if transport != nil {
				_ = server.SetReadDeadline(time.Now().Add(time.Second))
				_, err := server.Read(make([]byte, 1))
				require.ErrorIs(t, err, io.EOF)
			}
		})
	}
}
