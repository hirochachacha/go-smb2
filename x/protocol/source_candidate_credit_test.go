package protocol

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"time"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// Hold A's first transport write while it owns conn.m. B can then reserve
// credit through the normal Request.Send path without publishing a packet.
type candidateWriteGate struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (g *candidateWriteGate) Write(p []byte) (int, error) {
	g.once.Do(func() { close(g.entered); <-g.release })
	return g.Conn.Write(p)
}

func TestSourceCandidateUnsentCreditIdentifier(t *testing.T) {
	for _, laterLive := range []bool{false, true} {
		t.Run(map[bool]string{false: "two-credits", true: "three-credits-later-live"}[laterLive], func(t *testing.T) {
			func() {
				client, peer := net.Pipe()
				gate := &candidateWriteGate{Conn: client, entered: make(chan struct{}), release: make(chan struct{})}
				c, cleanup := newBenchConn(gate)
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(gate.release) }) }
				defer release()
				defer cleanup()
				defer peer.Close()
				credits := uint16(2)
				if laterLive {
					credits = 3
				}
				c.account = openAccount(credits)
				c.account.charge(credits - 1)
				c.session = &session{conn: c, sessionId: 0x100}
				c.enableSession()
				tree := &Tree{session: c.session, treeId: 0x200}
				ctx, cancelAll := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelAll()
				packets := make(chan uint64, 4)
				responderDone := make(chan error, 1)
				go func() {
					transport := NewTransport(peer)
					for {
						buf, err := transport.readPacket()
						if err != nil {
							responderDone <- err
							return
						}
						p := buf.codec()

						if p.IsInvalid() {
							buf.close()
							responderDone <- errors.New("invalid source-generated packet")
							return
						}
						id := p.MessageId()
						buf.close()
						packets <- id /* deliberately no responses or grants */
					}
				}()
				var senders sync.WaitGroup
				defer func() {
					cancelAll()
					release()
					_ = peer.Close()
					cleanup()
					senders.Wait()
					select {
					case err := <-responderDone:
						if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
							t.Errorf("responder: %v", err)
						}
					case <-time.After(time.Second):
						t.Error("responder did not finish")
					}
				}()
				send := func(ctx context.Context) <-chan error {
					done := make(chan error, 1)
					senders.Add(1)
					go func() {
						defer senders.Done()
						_, err := tree.Request().WithFileID(wire.FileId{Persistent: [8]byte{1}}).Read(1, 0).Send(ctx)
						done <- err
					}()
					return done
				}
				aDone := send(ctx)
				<-gate.entered
				bctx, cancelB := context.WithCancel(ctx)
				bDone := send(bctx)
				waitReserved(t, ctx, c.account, 2)
				var dDone <-chan error
				if laterLive {
					dDone = send(ctx)
					waitReserved(t, ctx, c.account, 3)
				}
				cancelB()
				release()
				if err := <-aDone; err != nil {
					t.Fatal(err)
				}
				if err := <-bDone; !errors.Is(err, context.Canceled) {
					t.Fatalf("B Send=%v", err)
				}
				if dDone != nil {
					if err := <-dDone; err != nil {
						t.Fatal(err)
					}
				}
				c.account.m.Lock()
				refunded := c.account.availableCredits
				c.account.m.Unlock()
				if refunded != 1 {
					t.Errorf("refunded count=%d; want 1", refunded)
				}
				cDone := send(ctx)
				if err := <-cDone; err != nil {
					t.Fatal(err)
				}
				count := 2
				if laterLive {
					count = 3
				}
				var ids []uint64
				for range count {
					ids = append(ids, <-packets)
				}
				t.Logf("granted IDs=[0,%d); B canceled unsent; source-generated wire IDs=%v; refunded count=%d; no response grants", credits, ids, refunded)
				// Membership is the requirement: no lowest-available ordering assumption.
				seen := map[uint64]bool{}
				for _, id := range ids {
					if id >= uint64(credits) {
						t.Errorf("wire MessageId %d was never granted (granted [0,%d))", id, credits)
					}
					if seen[id] {
						t.Errorf("duplicate wire MessageId %d", id)
					}
					seen[id] = true
				}
			}()
		})
	}
}

// Observe count reservations under their owning mutex, then open the next barrier.
// Do not depend on eager MessageId assignment: a repair can assign IDs at send.
// This avoids depending on scheduling delays or reading a request being built.
func waitReserved(t *testing.T, ctx context.Context, a *account, want uint16) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		a.m.Lock()
		got := a.inFlightCredits
		a.m.Unlock()
		if got == want {
			return
		}
		if got > want {
			t.Fatalf("reservation advanced to %d; want %d", got, want)
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("reservation barrier %d: %v", want, ctx.Err())
		}
	}
}

// Exercise local assembly failures through supported builders. The oversized
// CREATE and long directory pattern fail before any request bytes are sent.
func TestSourceCandidatePreparationCreditIdentifier(t *testing.T) {
	for _, kind := range []string{"packet-size", "compound-query-encoding"} {
		t.Run(kind, func(t *testing.T) {
			tree, peer := newTestTree(t)
			c := tree.conn
			c.account = openAccount(4)
			c.account.charge(3)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			wireIDs := make(chan uint64, 4)
			done := make(chan error, 1)
			go func() {
				transport := NewTransport(peer)
				for {
					packet, err := transport.readPacket()
					if err != nil {
						done <- err
						return
					}
					p := packet.codec()
					if p.IsInvalid() {
						packet.close()
						done <- errors.New("invalid source-generated packet")
						return
					}
					id := p.MessageId()
					packet.close()
					wireIDs <- id /* no responses or grants */
				}
			}()
			defer func() {
				_ = peer.Close()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("responder did not finish")
				}
			}()
			sendRead := func() {
				_, err := tree.Request().WithFileID(wire.FileId{Persistent: [8]byte{1}}).Read(1, 0).Send(ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			sendRead()
			if id := <-wireIDs; id != 0 {
				t.Fatalf("initial published ID=%d", id)
			}
			var request *Request
			var wantError string
			if kind == "packet-size" {
				request = tree.Request().Create(strings.Repeat("x", maxDirectTCPSize/2+1), wire.FILE_READ_DATA, wire.FILE_OPEN, 0, wire.FILE_ATTRIBUTE_NORMAL)
				wantError = "invalid packet size"
			} else {
				request = tree.Request().WithFileID(wire.FileId{Persistent: [8]byte{1}}).Read(65537, 0).QueryDir(wire.FileIdBothDirectoryInformation, strings.Repeat("x", 32768), 1024)
				wantError = "invalid encoded query directory request"
			}
			_, err := request.Send(ctx)
			if err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("preparation failure=%v; want %s", err, wantError)
			}
			c.account.m.Lock()
			next, available, inFlight := c.account.nextMessageId, c.account.availableCredits, c.account.inFlightCredits
			c.account.m.Unlock()
			c.outstandingRequests.m.Lock()
			outstanding := len(c.outstandingRequests.requests)
			c.outstandingRequests.m.Unlock()
			t.Logf("after unpublished preparation failure: next=%d available=%d inFlight=%d outstanding=%d", next, available, inFlight, outstanding)
			if available != 3 || inFlight != 1 || outstanding != 1 {
				t.Fatalf("unpublished preparation changed counts/registration")
			}
			if next != 1 {
				t.Errorf("unpublished suffix not restored: next=%d; want 1 (keep published ID 0)", next)
			}
			sendRead()
			if id := <-wireIDs; id != 1 {
				t.Errorf("next live ID=%d; want 1 after unpublished failure", id)
			}
		})
	}
}
