package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func installInterlinkTestReferral(t *testing.T, d *Client, prefix, target string, interlink bool) *referralEntry {
	t.Helper()
	flags := uint32(dfs.HeaderServers | dfs.HeaderStorage)
	if interlink {
		flags = dfs.HeaderServers
	}
	entry, err := d.installReferral(&dfs.ReferralResponse{
		HeaderFlags: flags, Prefix: prefix,
		Entries: []dfs.ReferralEntry{{Version: 3, ServerType: dfs.ServerRoot, TTL: time.Minute, NetworkAddress: target}},
	}, prefix+`\file`)
	require.NoError(t, err)
	return entry
}

// One version-3 root referral, with strings following its 34-byte entry.
func interlinkTestResponse(prefix, target string) []byte {
	path := append(utf16le.EncodeStringToBytes(prefix), 0, 0)
	network := append(utf16le.EncodeStringToBytes(target), 0, 0)
	b := make([]byte, 8+34+len(path)+len(network))
	le := binary.LittleEndian
	le.PutUint16(b[0:2], uint16(len(path)-2))
	le.PutUint16(b[2:4], 1)
	le.PutUint32(b[4:8], uint32(dfs.HeaderServers|dfs.HeaderStorage))
	e := b[8:]
	le.PutUint16(e[0:2], 3)
	le.PutUint16(e[2:4], 34)
	le.PutUint16(e[4:6], uint16(dfs.ServerRoot))
	le.PutUint32(e[8:12], 60)
	le.PutUint16(e[12:14], 34)
	le.PutUint16(e[14:16], 34)
	le.PutUint16(e[16:18], uint16(34+len(path)))
	copy(e[34:], path)
	copy(e[34+len(path):], network)
	return b
}

func TestInterlinkCacheContinuation(t *testing.T) {
	for _, state := range []string{"valid", "expired", "miss", "refresh"} {
		t.Run(state, func(t *testing.T) {
			next, storage, fresh := newClientTestEndpoint("next"), newClientTestEndpoint("storage"), newClientTestEndpoint("fresh")
			var queries atomic.Int32
			next.handleRequest = func(conn net.Conn, data []byte) bool {
				p := wire.PacketCodec(data)
				require.False(t, p.IsInvalid())
				if p.Command() != wire.SMB2_IOCTL {
					return false
				}
				r := wire.IoctlRequestDecoder(data[64:])
				require.False(t, r.IsInvalid())
				if r.CtlCode() != wire.FSCTL_DFS_GET_REFERRALS {
					return false
				}
				queries.Add(1)
				if state == "valid" {
					require.NoError(t, conn.Close()) // The namespace is temporarily unavailable.
					return true
				}
				writeFileRecoveryResponse(t, conn, data, &wire.IoctlResponse{
					CtlCode: r.CtlCode(), Output: clientTestBytes(interlinkTestResponse(`\next\root`, `\fresh\share`)),
				}, 0)
				return true
			}
			d := New(newClientTestDialer(&clientTestCredentials{}, next, storage, fresh))
			defer d.Close()
			installInterlinkTestReferral(t, d, `\\namespace\root\link`, `\next\root`, true)
			if state != "miss" {
				entry := installInterlinkTestReferral(t, d, `\\next\root`, `\storage\share`, false)
				if state == "expired" {
					d.mu.Lock()
					entry.expires = time.Now().Add(-time.Second)
					d.mu.Unlock()
				}
			}
			var servers []string
			_, err := d.execute(context.Background(), `\\namespace\root\link\file`, func(_ context.Context, route *resolvedRoute) (any, error) {
				servers = append(servers, route.path.Server)
				require.Equal(t, "file", route.path.RelPath)
				if state == "refresh" && len(servers) == 1 {
					return nil, &protocol.DFSReferralRequiredError{Path: `\\next\root\file`}
				}
				return nil, nil
			})
			require.NoError(t, err)
			if state == "valid" {
				file, err := d.Open(context.Background(), `\\namespace\root\link\file`)
				require.NoError(t, err)
				require.NoError(t, file.Close(context.Background()))
				require.Zero(t, queries.Load())
				require.Equal(t, []string{"storage"}, servers)
			} else {
				require.EqualValues(t, 1, queries.Load())
				if state == "refresh" {
					require.Equal(t, []string{"storage", "fresh"}, servers)
				} else {
					require.Equal(t, []string{"fresh"}, servers)
				}
			}
		})
	}
}

func TestInterlinkCacheChainAndCycles(t *testing.T) {
	for _, kind := range []string{"chain", "self", "cycle", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			storage := newClientTestEndpoint("storage")
			d := New(newClientTestDialer(&clientTestCredentials{}, storage))
			defer d.Close()
			installInterlinkTestReferral(t, d, `\\a\root`, `\b\root`, true)
			switch kind {
			case "chain":
				installInterlinkTestReferral(t, d, `\\b\root`, `\c\root`, true)
				installInterlinkTestReferral(t, d, `\\c\root`, `\storage\share`, false)
			case "self":
				installInterlinkTestReferral(t, d, `\\b\root`, `\b\root`, true)
			default:
				installInterlinkTestReferral(t, d, `\\b\root`, `\a\root`, true)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "canceled" {
				cancel()
			}
			calls := 0
			_, err := d.execute(ctx, `\\a\root\file`, func(_ context.Context, route *resolvedRoute) (any, error) {
				calls++
				require.Equal(t, "storage", route.path.Server)
				require.Equal(t, `\\storage\share\file`, route.path.String())
				return nil, nil
			})
			switch kind {
			case "chain":
				require.NoError(t, err)
				require.Equal(t, 1, calls)
			case "canceled":
				require.ErrorIs(t, err, context.Canceled)
				require.Zero(t, calls)
			default:
				require.ErrorIs(t, err, errReferralDepth)
				require.Zero(t, calls)
			}
		})
	}
}

func TestInterlinkNamespaceFailure(t *testing.T) {
	for _, mode := range []string{"query", "cache", "all-down", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			first, next, storage := newClientTestEndpoint("first"), newClientTestEndpoint("next"), newClientTestEndpoint("storage")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var firstQueries, nextQueries atomic.Int32
			for _, ep := range []*clientTestEndpoint{first, next} {
				ep.handleRequest = func(conn net.Conn, data []byte) bool {
					p := wire.PacketCodec(data)
					require.False(t, p.IsInvalid())
					if p.Command() != wire.SMB2_IOCTL {
						return false
					}
					r := wire.IoctlRequestDecoder(p.Body())
					require.False(t, r.IsInvalid())
					require.Equal(t, uint32(wire.FSCTL_DFS_GET_REFERRALS), r.CtlCode())
					if ep == first {
						firstQueries.Add(1)
						if mode == "canceled" {
							cancel()
						}
						require.NoError(t, conn.Close())
					} else {
						nextQueries.Add(1)
						if mode == "all-down" {
							require.NoError(t, conn.Close())
						} else {
							writeFileRecoveryResponse(t, conn, data, &wire.IoctlResponse{
								CtlCode: r.CtlCode(), Output: clientTestBytes(interlinkTestResponse(`\next\root`, `\storage\share`)),
							}, 0)
						}
					}
					return true
				}
			}
			d := New(newClientTestDialer(&clientTestCredentials{}, first, next, storage))
			defer d.Close()
			const path = `\\namespace\root\link\file`
			entry, err := d.installReferral(&dfs.ReferralResponse{
				HeaderFlags: dfs.HeaderServers, Prefix: `\\namespace\root\link`,
				Entries: []dfs.ReferralEntry{
					{Version: 3, ServerType: dfs.ServerRoot, TTL: time.Minute, NetworkAddress: `\first\root`},
					{Version: 3, ServerType: dfs.ServerRoot, TTL: time.Minute, NetworkAddress: `\next\root`},
				},
			}, path)
			require.NoError(t, err)
			if mode == "cache" || mode == "canceled" {
				installInterlinkTestReferral(t, d, `\\next\root`, `\storage\share`, false)
			}
			file, err := d.Open(ctx, path)
			if mode == "all-down" || mode == "canceled" {
				require.Nil(t, file)
				var pe *os.PathError
				require.ErrorAs(t, err, &pe)
				require.Equal(t, "open", pe.Op)
				require.Equal(t, path, pe.Path)
				if mode == "all-down" {
					require.ErrorIs(t, err, io.EOF)
					var transport *protocol.TransportError
					require.ErrorAs(t, err, &transport)
					require.EqualValues(t, 1, nextQueries.Load())
				} else {
					require.ErrorIs(t, err, context.Canceled)
					require.Zero(t, nextQueries.Load())
				}
			} else {
				require.NoError(t, err)
				require.NoError(t, file.Close(ctx))
				file, err = d.Open(ctx, path)
				require.NoError(t, err)
				require.NoError(t, file.Close(ctx))
				if mode == "query" {
					require.EqualValues(t, 1, nextQueries.Load())
				} else {
					require.Zero(t, nextQueries.Load())
				}
			}
			require.EqualValues(t, 1, firstQueries.Load())
			first.mu.Lock()
			firstDials := first.dials
			first.mu.Unlock()
			require.Equal(t, 1, firstDials, "the next operation must reuse the selected namespace hint")
			storage.mu.Lock()
			storageCreates := storage.creates
			storage.mu.Unlock()
			d.mu.Lock()
			hint := entry.hint
			d.mu.Unlock()
			if mode == "query" || mode == "cache" {
				require.Equal(t, 1, hint)
				require.Equal(t, 2, storageCreates)
			} else {
				require.Zero(t, hint)
				require.Zero(t, storageCreates)
			}
		})
	}
}
