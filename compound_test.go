package smb2

import (
	"context"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompoundWithOneCredit(t *testing.T) {
	for _, test := range []struct {
		name       string
		fail       smb2.Command
		limit      uint16
		largeQuery bool
	}{
		{name: "success"},
		{name: "configured one credit", limit: 1},
		{name: "create fails", fail: smb2.SMB2_CREATE},
		{name: "query fails", fail: smb2.SMB2_QUERY_INFO},
		{name: "query exceeds idle window", largeQuery: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fs, serverConn := newTestShare(t)
			limit := test.limit
			if limit == 0 {
				limit = 128
			}
			fs.conn.account = openAccount(limit) // Server never grants more than one.
			dt := direct(serverConn)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer serverConn.Close()
				for attempt := byte(1); attempt <= 2; attempt++ {
					fileID := &smb2.FileId{Persistent: [8]byte{attempt}, Volatile: [8]byte{9}}
					commands := []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_QUERY_INFO, smb2.SMB2_CLOSE}
					if test.fail == smb2.SMB2_CREATE {
						commands = commands[:1]
					}
					if test.largeQuery {
						commands = []smb2.Command{smb2.SMB2_CREATE, smb2.SMB2_CLOSE}
					}
					for _, cmd := range commands {
						req, err := readMsg(dt)
						if err != nil {
							t.Error(err)
							return
						}
						p := smb2.PacketCodec(req)
						assert.Equal(t, cmd, p.Command())
						assert.Zero(t, p.NextCommand())
						assert.Zero(t, p.Flags()&smb2.SMB2_FLAGS_RELATED_OPERATIONS)
						assert.Equal(t, fs.treeId, p.TreeId())
						assert.Equal(t, fs.sessionId, p.SessionId())
						if cmd == smb2.SMB2_QUERY_INFO {
							assert.Equal(t, *fileID, *smb2.QueryInfoRequestDecoder(p.Body()).FileId().Decode())
						}
						if cmd == smb2.SMB2_CLOSE {
							assert.Equal(t, *fileID, *smb2.CloseRequestDecoder(p.Body()).FileId().Decode())
						}
						if cmd == test.fail {
							sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: cmd}, uint32(erref.STATUS_ACCESS_DENIED))
							continue
						}
						switch cmd {
						case smb2.SMB2_CREATE:
							sendTestCreateAttributesResponse(dt, req, fileID, smb2.FILE_ATTRIBUTE_NORMAL)
						case smb2.SMB2_QUERY_INFO:
							sendTestResponse(dt, req, &smb2.QueryInfoResponse{Output: rawEncoder(make([]byte, 24))}, uint32(erref.STATUS_SUCCESS))
						case smb2.SMB2_CLOSE:
							sendTestCloseResponse(dt, req)
						}
					}
				}
			}()
			req := fs.request().create("file", smb2.GENERIC_READ, smb2.FILE_OPEN, 0, 0).
				queryInfo(smb2.SMB2_0_INFO_FILE, smb2.FileStandardInformation, 0, 24).close()
			if test.largeQuery {
				req.get(1).(*smb2.QueryInfoRequest).OutputBufferLength = 2 * singleCreditMaxPayloadSize
			}
			for attempt := 0; attempt < 2; attempt++ {
				res, err := req.sendRecv(context.Background())
				if test.largeQuery {
					var internal *InternalError
					require.ErrorAs(t, err, &internal)
				} else if test.fail != 0 {
					require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
					var compound *CompoundResponseError
					require.ErrorAs(t, err, &compound)
					if test.fail == smb2.SMB2_QUERY_INFO {
						require.NoError(t, compound.OpError(0))
					}
				} else {
					require.NoError(t, err)
					require.Len(t, res.rpkts, 3)
					res.close()
				}
				// Retrying the builder must resolve a newly opened handle again.
				require.True(t, req.get(1).(*smb2.QueryInfoRequest).FileId.IsRelated())
				require.True(t, req.get(2).(*smb2.CloseRequest).FileId.IsRelated())
			}
			<-done
		})
	}
}

func TestIdleCreditWindow(t *testing.T) {
	a := openAccount(128)
	_, _, err := a.loan(context.Background(), &smb2.ReadRequest{Length: 2 * singleCreditMaxPayloadSize})
	require.IsType(t, &InternalError{}, err)
	require.Zero(t, a.inFlightCredits)
	require.Equal(t, uint16(1), a.availableCredits)

	_, _, err = a.loan(context.Background(), &smb2.CreateRequest{}, &smb2.CloseRequest{})
	require.ErrorIs(t, err, errCompoundCredits)
	require.Zero(t, a.inFlightCredits)
	require.Zero(t, a.nextMessageId)

	// An existing request can still replenish the window. Do not force a
	// sequential send while that response could supply the required credits.
	_, _, err = a.loan(context.Background(), &smb2.CreateRequest{})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, _, err := a.loan(context.Background(), &smb2.CreateRequest{}, &smb2.CloseRequest{})
		done <- err
	}()
	a.charge(2, 1)
	require.NoError(t, <-done)
}

func TestSequentialCanceledCloseIsNotRepeated(t *testing.T) {
	fs, serverConn := newTestShare(t)
	fs.conn.account = openAccount(128)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fileID := &smb2.FileId{Persistent: [8]byte{3}, Volatile: [8]byte{4}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		dt := direct(serverConn)
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
		assert.Equal(t, smb2.SMB2_CLOSE, smb2.PacketCodec(closeReq).Command())
		cancel()
		canceled, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		assert.Equal(t, smb2.SMB2_CANCEL, smb2.PacketCodec(canceled).Command())
		sendTestCloseResponse(dt, closeReq)
		probe, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		assert.Equal(t, smb2.SMB2_FLUSH, smb2.PacketCodec(probe).Command(), "must not send a second CLOSE")
		sendTestResponse(dt, probe, &smb2.FlushResponse{}, uint32(erref.STATUS_SUCCESS))
	}()
	res, err := fs.request().create("file", smb2.GENERIC_READ, smb2.FILE_OPEN, 0, 0).close().sendRecv(ctx)
	res.close()
	require.ErrorIs(t, err, context.Canceled)
	res, err = fs.request().withFileId(fileID).flush().sendRecv(context.Background())
	require.NoError(t, err)
	res.close()
	<-done
}
