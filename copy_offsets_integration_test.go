package smb2_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

// TestServerSideCopyOffsets checks file contents independently of the server's
// success status and byte counts. All files belong to the test's private directory.
func TestServerSideCopyOffsets(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		dir := newTestDirectory(t, e.fs)
		const sourceText = "AAAABBBBCCCC"
		const destinationText = "0123456789abcdef"
		source := pathpkg.Join(dir, "source")
		require.NoError(t, e.fs.WriteFile(ctx, source, []byte(sourceText), 0600))
		src, err := e.fs.Open(ctx, source)
		require.NoError(t, err)
		defer src.Close(context.Background())
		res, err := e.fs.Request().WithFileID(src.Fd()).Ioctl(wire.FSCTL_SRV_REQUEST_RESUME_KEY, nil, 32).Do(ctx)
		require.NoError(t, err)
		out, err := res.Ioctl(0)
		require.NoError(t, err)
		key, err := out.SrvRequestResumeKey()
		require.NoError(t, err)
		var sourceKey [24]byte
		copy(sourceKey[:], key.ResumeKey())
		res.Close()
		for _, code := range []uint32{wire.FSCTL_SRV_COPYCHUNK, wire.FSCTL_SRV_COPYCHUNK_WRITE} {
			t.Run(fmt.Sprintf("ctl_%08x", code), func(t *testing.T) {
				for _, tc := range []struct {
					name   string
					chunks []wire.SrvCopychunk
				}{
					{"zero", []wire.SrvCopychunk{{SourceOffset: 0, TargetOffset: 0, Length: 4}}},
					{"equal_nonzero", []wire.SrvCopychunk{{SourceOffset: 4, TargetOffset: 4, Length: 4}}},
					{"source", []wire.SrvCopychunk{{SourceOffset: 4, TargetOffset: 0, Length: 4}}},
					{"target", []wire.SrvCopychunk{{SourceOffset: 0, TargetOffset: 6, Length: 4}}},
					{"both", []wire.SrvCopychunk{{SourceOffset: 4, TargetOffset: 6, Length: 4}}},
					{"unaligned", []wire.SrvCopychunk{{SourceOffset: 3, TargetOffset: 5, Length: 3}}},
					{"extend", []wire.SrvCopychunk{{SourceOffset: 8, TargetOffset: 16, Length: 4}}},
					{"whole_source", []wire.SrvCopychunk{{SourceOffset: 0, TargetOffset: 0, Length: 12}}},
					{"two_chunks", []wire.SrvCopychunk{{SourceOffset: 4, TargetOffset: 2, Length: 4}, {SourceOffset: 8, TargetOffset: 10, Length: 4}}},
				} {
					t.Run(tc.name, func(t *testing.T) {
						name := pathpkg.Join(dir, fmt.Sprintf("dest-%x-%s", code, tc.name))
						require.NoError(t, e.fs.WriteFile(ctx, name, []byte(destinationText), 0600))
						dst, err := e.fs.OpenFile(ctx, name, os.O_RDWR, 0600)
						require.NoError(t, err)
						defer dst.Close(context.Background())
						request := &wire.SrvCopychunkCopy{SourceKey: sourceKey, Chunks: tc.chunks}
						encoded := make([]byte, request.Size())
						request.Encode(encoded)
						// Omit the opaque resume key; only public test inputs are logged.
						t.Logf("chunks=%+v encoded_chunks=%x", tc.chunks, encoded[32:])
						response, err := e.fs.Request().WithFileID(dst.Fd()).Ioctl(code, request, 24).Do(ctx)
						if errors.Is(err, erref.STATUS_NOT_SUPPORTED) || errors.Is(err, erref.STATUS_INVALID_DEVICE_REQUEST) {
							t.Skipf("copy control not supported: %v", err)
						}
						require.NoError(t, err)
						ioctl, err := response.Ioctl(0)
						require.NoError(t, err)
						counts := wire.SrvCopychunkResponseDecoder(ioctl.Output())
						require.False(t, counts.IsInvalid())
						_, validationErr := ioctl.SrvCopychunk()
						t.Logf("status=SUCCESS chunks_written=%d chunk_bytes_written=%d total_bytes_written=%d validation_error=%v", counts.ChunksWritten(), counts.ChunksBytesWritten(), counts.TotalBytesWritten(), validationErr)
						response.Close()
						require.NoError(t, dst.Close(ctx))
						actual, err := e.fs.ReadFile(ctx, name)
						require.NoError(t, err)
						expected := []byte(destinationText)
						for _, chunk := range tc.chunks {
							end := int(chunk.TargetOffset) + int(chunk.Length)
							if end > len(expected) {
								expected = append(expected, make([]byte, end-len(expected))...)
							}
							copy(expected[int(chunk.TargetOffset):end], sourceText[int(chunk.SourceOffset):int(chunk.SourceOffset)+int(chunk.Length)])
						}
						t.Logf("expected=%q actual=%q", expected, actual)
						require.NoError(t, validationErr)
						require.Equal(t, string(expected), string(actual))
					})
				}
			})
		}
		unchanged, err := e.fs.ReadFile(ctx, source)
		require.NoError(t, err)
		require.Equal(t, sourceText, string(unchanged))
	})
}
