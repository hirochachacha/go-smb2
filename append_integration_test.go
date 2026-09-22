package smb2_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/stretchr/testify/require"
)

// TestAppendIntegration exercises single-writer append semantics tracked in TODO.md.
// It currently exposes server-backed failures; -short skips it.
func TestAppendIntegration(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		dir := newTestDirectory(t, e.fs)
		for _, trunc := range []bool{false, true} {
			t.Run(fmt.Sprintf("write_truncate_%t", trunc), func(t *testing.T) {
				name := pathpkg.Join(dir, fmt.Sprintf("write-%t", trunc))
				require.NoError(t, e.fs.WriteFile(ctx, name, []byte("old"), 0600))
				flags := os.O_RDWR | os.O_APPEND
				if trunc {
					flags |= os.O_TRUNC
				}
				f, err := e.fs.OpenFile(ctx, name, flags, 0600)
				require.NoError(t, err)
				defer f.Close(context.Background())
				_, err = f.Write(ctx, []byte("A"))
				require.NoError(t, err)
				_, err = f.Write(ctx, []byte("B"))
				require.NoError(t, err)
				_, err = f.Write(ctx, []byte("C"))
				require.NoError(t, err)
				actual, err := e.fs.ReadFile(ctx, name)
				require.NoError(t, err)
				want := "ABC"
				if !trunc {
					want = "oldABC"
				}
				require.Equal(t, want, string(actual))
			})
		}
		t.Run("large_write", func(t *testing.T) {
			name := pathpkg.Join(dir, "large")
			require.NoError(t, e.fs.WriteFile(ctx, name, []byte("prefix"), 0600))
			f, err := e.fs.OpenFile(ctx, name, os.O_WRONLY|os.O_APPEND, 0600)
			require.NoError(t, err)
			defer f.Close(context.Background())
			payload := make([]byte, 3*1024*1024)
			for i := range payload {
				payload[i] = byte(i / 4096)
			}
			n, err := f.Write(ctx, payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			actual, err := e.fs.ReadFile(ctx, name)
			require.NoError(t, err)
			require.True(t, bytes.Equal(append([]byte("prefix"), payload...), actual), "large append lost or reordered bytes")
		})
		for _, readFrom := range []bool{false, true} {
			t.Run(fmt.Sprintf("copy_readfrom_%t", readFrom), func(t *testing.T) {
				source := pathpkg.Join(dir, fmt.Sprintf("source-%t", readFrom))
				dest := pathpkg.Join(dir, fmt.Sprintf("dest-%t", readFrom))
				payload := bytes.Repeat([]byte("copy"), 1024)
				require.NoError(t, e.fs.WriteFile(ctx, source, payload, 0600))
				require.NoError(t, e.fs.WriteFile(ctx, dest, []byte("prefix"), 0600))
				src, err := e.fs.Open(ctx, source)
				require.NoError(t, err)
				defer src.Close(context.Background())
				dst, err := e.fs.OpenFile(ctx, dest, os.O_RDWR|os.O_APPEND, 0600)
				require.NoError(t, err)
				defer dst.Close(context.Background())
				var n int64
				if readFrom {
					n, err = dst.ReadFrom(ctx, src.WithContext(ctx))
				} else {
					n, err = src.WriteTo(ctx, dst.WithContext(ctx))
				}
				require.NoError(t, err)
				require.Equal(t, int64(len(payload)), n)
				actual, err := e.fs.ReadFile(ctx, dest)
				require.NoError(t, err)
				require.True(t, bytes.Equal(append([]byte("prefix"), payload...), actual), "copy did not append")
			})
		}
	})
}
