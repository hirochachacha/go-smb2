package protocol

import (
	"context"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompoundWithOneCredit(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		fail       wire.Command
		limit      uint16
		largeQuery bool
	}{
		{name: "success"},
		{name: "configured one credit", limit: 1},
		{name: "create fails", fail: wire.SMB2_CREATE},
		{name: "query fails", fail: wire.SMB2_QUERY_INFO},
		{name: "query exceeds idle window", largeQuery: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tc, serverConn := newTestTree(t)
			limit := test.limit
			if limit == 0 {
				limit = 128
			}
			tc.session.conn.account = openAccount(limit) // Server never grants more than one.
			dt := NewTransport(serverConn)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer serverConn.Close()
				for attempt := byte(1); attempt <= 2; attempt++ {
					fileID := wire.FileId{Persistent: [8]byte{attempt}, Volatile: [8]byte{9}}
					commands := []wire.Command{wire.SMB2_CREATE, wire.SMB2_QUERY_INFO, wire.SMB2_CLOSE}
					if test.fail == wire.SMB2_CREATE {
						commands = commands[:1]
					}
					if test.largeQuery {
						commands = []wire.Command{wire.SMB2_CREATE, wire.SMB2_CLOSE}
					}
					for _, cmd := range commands {
						req, err := readMsg(dt)
						if err != nil {
							t.Error(err)
							return
						}
						p := wire.PacketCodec(req)
						assert.Equal(t, cmd, p.Command())
						assert.Zero(t, p.NextCommand())
						assert.Zero(t, p.Flags()&wire.SMB2_FLAGS_RELATED_OPERATIONS)
						assert.Equal(t, tc.treeId, p.TreeId())
						assert.Equal(t, tc.sessionId, p.SessionId())
						if cmd == wire.SMB2_QUERY_INFO {
							assert.Equal(t, fileID, wire.QueryInfoRequestDecoder(p.Body()).FileId().Decode())
						}
						if cmd == wire.SMB2_CLOSE {
							assert.Equal(t, fileID, wire.CloseRequestDecoder(p.Body()).FileId().Decode())
						}
						if cmd == test.fail {
							sendTestResponse(dt, req, &wire.ErrorResponse{CommandCode: cmd}, uint32(erref.STATUS_ACCESS_DENIED))
							continue
						}
						switch cmd {
						case wire.SMB2_CREATE:
							sendTestCreateAttributesResponse(dt, req, fileID, wire.FILE_ATTRIBUTE_NORMAL)
						case wire.SMB2_QUERY_INFO:
							sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(make([]byte, 24))}, uint32(erref.STATUS_SUCCESS))
						case wire.SMB2_CLOSE:
							sendTestCloseResponse(dt, req)
						}
					}
				}
			}()
			req := tc.Request().Create("file", wire.GENERIC_READ, wire.FILE_OPEN, 0, 0).
				QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation, 0, 24).Close()
			if test.largeQuery {
				req.Get(1).(*wire.QueryInfoRequest).OutputBufferLength = 2 * maxSingleCreditPayloadSize
			}
			for range 2 {
				res, err := req.Do(context.Background())
				if test.largeQuery {
					require.ErrorContains(t, err, "protocol: requested credit charge exceeds idle credit window")
				} else if test.fail != 0 {
					require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
					var compound *CompoundResponseError
					require.ErrorAs(t, err, &compound)
					if test.fail == wire.SMB2_QUERY_INFO {
						require.NoError(t, compound.OpError(0))
					}
				} else {
					require.NoError(t, err)
					require.Len(t, res.rpkts, 3)
					query, err := res.QueryInfo(1)
					require.NoError(t, err)
					info, err := query.FileStandardInformation()
					require.NoError(t, err)
					require.Zero(t, info.EndOfFile())
					res.Close()
				}
				// Retrying the builder must resolve a newly opened handle again.
				require.True(t, req.Get(1).(*wire.QueryInfoRequest).FileId.IsRelated())
				require.True(t, req.Get(2).(*wire.CloseRequest).FileId.IsRelated())
			}
			<-done
		})
	}
}

func TestIdleCreditWindow(t *testing.T) {
	t.Parallel()
	a := openAccount(128)
	_, _, err := a.loan(context.Background(), &wire.ReadRequest{Length: 2 * maxSingleCreditPayloadSize})
	require.ErrorContains(t, err, "protocol: requested credit charge exceeds idle credit window")
	require.Zero(t, a.inFlightCredits)
	require.Equal(t, uint16(1), a.availableCredits)

	_, _, err = a.loan(context.Background(), &wire.CreateRequest{}, &wire.CloseRequest{})
	require.ErrorIs(t, err, errCompoundCredits)
	require.Zero(t, a.inFlightCredits)
	require.Zero(t, a.nextMessageId)

	// An existing request can still replenish the window. Do not force a
	// sequential send while that Response could supply the required credits.
	_, _, err = a.loan(context.Background(), &wire.CreateRequest{})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, _, err := a.loan(context.Background(), &wire.CreateRequest{}, &wire.CloseRequest{})
		done <- err
	}()
	a.charge(2, 1)
	require.NoError(t, <-done)
}

func TestSequentialCanceledCloseIsNotRepeated(t *testing.T) {
	t.Parallel()
	tc, serverConn := newTestTree(t)
	tc.session.conn.account = openAccount(128)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fileID := wire.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		dt := NewTransport(serverConn)
		create, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		sendTestCreateAttributesResponse(dt, create, fileID, 0)
		closeReq, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		assert.Equal(t, wire.SMB2_CLOSE, wire.PacketCodec(closeReq).Command())
		cancel()
		canceled, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		assert.Equal(t, wire.SMB2_CANCEL, wire.PacketCodec(canceled).Command())
		sendTestCloseResponse(dt, closeReq)
		probe, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		assert.Equal(t, wire.SMB2_FLUSH, wire.PacketCodec(probe).Command(), "must not send a second CLOSE")
		sendTestResponse(dt, probe, &wire.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
	}()
	res, err := tc.Request().Create("file", wire.GENERIC_READ, wire.FILE_OPEN, 0, 0).Close().Do(ctx)
	if res != nil {
		res.Close()
	}
	require.ErrorIs(t, err, context.Canceled)
	res, err = tc.Request().WithFileID(fileID).Flush().Do(context.Background())
	require.NoError(t, err)
	res.Close()
	<-done
}
