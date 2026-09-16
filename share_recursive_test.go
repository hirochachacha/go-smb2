package smb2

import (
	"context"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/stretchr/testify/require"
)

func TestRemoveAllFollowsParentSymlink(t *testing.T) {
	t.Parallel()
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			fs, server := newTestShare(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				dt := direct(server)
				read := func(command smb2.Command, name string) []byte {
					req, err := readMsg(dt)
					if err != nil {
						t.Error(err)
						return nil
					}
					p := smb2.PacketCodec(req)
					if p.Command() != command {
						t.Errorf("command = %v, want %v", p.Command(), command)
						return nil
					}
					if command == smb2.SMB2_CREATE {
						cr := smb2.CreateRequestDecoder(p.Body())
						start, size := int(cr.NameOffset()), int(cr.NameLength())
						if got := utf16le.DecodeToString(req[start : start+size]); got != name {
							t.Errorf("name = %q, want %q", got, name)
						}
						if cr.CreateOptions()&smb2.FILE_OPEN_REPARSE_POINT == 0 {
							t.Error("CREATE must open the final link itself")
						}
					}
					return req
				}
				stopped := func(req []byte, compound bool) {
					responses := []compoundResponse{{
						packet: &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE, ErrorData: &smb2.SymbolicLinkErrorResponse{
							UnparsedPathLength: uint16(utf16le.EncodedStringLen(`\item`)),
							Flags:              smb2.SYMLINK_FLAG_RELATIVE, SubstituteName: "target", PrintName: "target",
						}}, status: erref.STATUS_STOPPED_ON_SYMLINK,
					}}
					if compound {
						for _, cmd := range []smb2.Command{smb2.SMB2_SET_INFO, smb2.SMB2_CLOSE} {
							responses = append(responses, compoundResponse{packet: &smb2.ErrorResponse{CommandCode: cmd}, status: erref.STATUS_INVALID_HANDLE})
						}
					}
					if err := sendCompoundResponse(dt, req, responses); err != nil {
						t.Error(err)
					}
				}
				req := read(smb2.SMB2_CREATE, `link\item`)
				if req == nil {
					return
				}
				stopped(req, true)
				req = read(smb2.SMB2_CREATE, `target\item`)
				if req == nil {
					return
				}
				if !directory {
					sendTestCompoundSuccessResponse(dt, req)
					return
				}
				sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))

				// Opening a nonempty directory must also resolve the parent link.
				req = read(smb2.SMB2_CREATE, `link\item`)
				if req == nil {
					return
				}
				stopped(req, false)
				req = read(smb2.SMB2_CREATE, `target\item`)
				if req == nil {
					return
				}
				cr := smb2.CreateRequestDecoder(smb2.PacketCodec(req).Body())
				if cr.ShareAccess()&smb2.FILE_SHARE_DELETE != 0 {
					t.Error("directory must remain pinned")
				}
				sendTestCreateAttributesResponse(dt, req, &smb2.FileId{}, smb2.FILE_ATTRIBUTE_DIRECTORY)
				req = read(smb2.SMB2_QUERY_DIRECTORY, "")
				if req == nil {
					return
				}
				// A child link is removed directly, never opened for enumeration.
				sendTestResponse(dt, req, &smb2.QueryDirectoryResponse{Output: rawEncoder(encodeFileIdBothDirectoryInformation("child-link"))}, 0)
				req = read(smb2.SMB2_QUERY_DIRECTORY, "")
				if req == nil {
					return
				}
				sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_NO_MORE_FILES))
				req = read(smb2.SMB2_CREATE, `target\item\child-link`)
				if req == nil {
					return
				}
				sendTestCompoundSuccessResponse(dt, req)
				req = read(smb2.SMB2_CLOSE, "")
				if req == nil {
					return
				}
				sendTestCloseResponse(dt, req)
				req = read(smb2.SMB2_CREATE, `target\item`)
				if req == nil {
					return
				}
				sendTestCompoundSuccessResponse(dt, req)
			}()
			require.NoError(t, fs.RemoveAll(ctx, `link\item`))
			<-done
		})
	}
}

func TestRemoveAllDoesNotTraverseTargetSymlink(t *testing.T) {
	t.Parallel()
	fs, server := newTestShare(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := direct(server)
		req, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		// If direct deletion fails, opening the target must not lead to
		// enumerating a link's contents, even if it is marked as a directory.
		sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_SHARING_VIOLATION))
		req, err = readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		cr := smb2.CreateRequestDecoder(smb2.PacketCodec(req).Body())
		if cr.CreateOptions()&smb2.FILE_OPEN_REPARSE_POINT == 0 {
			t.Error("CREATE followed the target link")
		}
		sendTestCreateAttributesResponse(dt, req, &smb2.FileId{}, smb2.FILE_ATTRIBUTE_DIRECTORY|smb2.FILE_ATTRIBUTE_REPARSE_POINT)
		req, err = readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		if got := smb2.PacketCodec(req).Command(); got != smb2.SMB2_CLOSE {
			t.Errorf("command = %v, want CLOSE without enumeration", got)
			return
		}
		sendTestCloseResponse(dt, req)
	}()
	require.ErrorIs(t, fs.RemoveAll(ctx, "link"), erref.STATUS_SHARING_VIOLATION)
	<-done
	requireNoRequest(t, server)
}

func TestRemoveAllReopensDirectory(t *testing.T) {
	t.Parallel()
	fs, server := newTestShare(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := direct(server)
		opens, removes, queries := 0, 0, 0
		for {
			req, err := readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			p := smb2.PacketCodec(req)
			switch p.Command() {
			case smb2.SMB2_CREATE:
				cr := smb2.CreateRequestDecoder(p.Body())
				start, size := int(cr.NameOffset()), int(cr.NameLength())
				name := utf16le.DecodeToString(req[start : start+size])
				if cr.DesiredAccess()&smb2.DELETE == 0 {
					opens++
					sendTestCreateAttributesResponse(dt, req, &smb2.FileId{}, smb2.FILE_ATTRIBUTE_DIRECTORY)
				} else if name == `root\child` {
					sendTestCompoundSuccessResponse(dt, req)
				} else {
					removes++
					if removes < 3 {
						sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
					} else {
						if opens != 2 {
							t.Errorf("directory opens = %d, want 2", opens)
						}
						sendTestCompoundSuccessResponse(dt, req)
						return
					}
				}
			case smb2.SMB2_QUERY_DIRECTORY:
				queries++
				if queries == 1 {
					sendTestResponse(dt, req, &smb2.QueryDirectoryResponse{Output: rawEncoder(encodeFileIdBothDirectoryInformation("child"))}, 0)
				} else {
					sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: p.Command()}, uint32(erref.STATUS_NO_MORE_FILES))
				}
			case smb2.SMB2_CLOSE:
				sendTestCloseResponse(dt, req)
			default:
				t.Errorf("unexpected command %v", p.Command())
				return
			}
		}
	}()
	require.NoError(t, fs.RemoveAll(ctx, "root"))
	<-done
}

func TestRemoveAllFinalRemovalOverridesReadError(t *testing.T) {
	t.Parallel()
	fs, server := newTestShare(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := direct(server)
		for step := 0; step < 5; step++ {
			req, err := readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			switch step {
			case 0:
				sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_DIRECTORY_NOT_EMPTY))
			case 1:
				sendTestCreateAttributesResponse(dt, req, &smb2.FileId{}, smb2.FILE_ATTRIBUTE_DIRECTORY)
			case 2:
				sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_QUERY_DIRECTORY}, uint32(erref.STATUS_ACCESS_DENIED))
			case 3:
				sendTestCloseResponse(dt, req)
			case 4:
				sendTestCompoundSuccessResponse(dt, req)
			}
		}
	}()
	require.NoError(t, fs.RemoveAll(ctx, "root"))
	<-done
}

func TestRemoveAllNonDirectory(t *testing.T) {
	t.Parallel()
	for _, parentIsFile := range []bool{false, true} {
		name := "target is file"
		if parentIsFile {
			name = "parent is file"
		}
		t.Run(name, func(t *testing.T) {
			fs, server := newTestShare(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				dt := direct(server)
				req, err := readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				sendTestCompoundErrorResponse(dt, req, uint32(erref.STATUS_SHARING_VIOLATION))
				req, err = readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				if parentIsFile {
					sendTestResponse(dt, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_CREATE}, uint32(erref.STATUS_NOT_A_DIRECTORY))
					return
				}
				cr := smb2.CreateRequestDecoder(smb2.PacketCodec(req).Body())
				if cr.CreateOptions()&smb2.FILE_DIRECTORY_FILE != 0 {
					t.Error("open must allow inspecting a non-directory target")
				}
				sendTestCreateAttributesResponse(dt, req, &smb2.FileId{}, smb2.FILE_ATTRIBUTE_NORMAL)
				req, err = readMsg(dt)
				if err != nil {
					t.Error(err)
					return
				}
				sendTestCloseResponse(dt, req)
			}()
			err := fs.RemoveAll(ctx, `parent\target`)
			if parentIsFile {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, erref.STATUS_SHARING_VIOLATION)
			}
			<-done
		})
	}
}
