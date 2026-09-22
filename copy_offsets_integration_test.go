package smb2_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	pathpkg "github.com/hirochachacha/go-smb2/v2/internal/path"
	"github.com/stretchr/testify/require"
)

// TestServerSideCopyOffsets covers the File API's choice between server-side copy
// and ordinary reads/writes, including the workaround for unequal offsets.
func TestServerSideCopyOffsets(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		dir := newTestDirectory(t, e.fs)
		const sourceText = "AAAABBBBCCCCDDDDEEEEFFFF"
		const destinationText = "0123456789abcdef"
		source := pathpkg.Join(dir, "source")
		require.NoError(t, e.fs.WriteFile(ctx, source, []byte(sourceText), 0600))
		for _, readFrom := range []bool{false, true} {
			for _, tc := range []struct {
				name           string
				source, target int64
				appendMode     bool
			}{
				{"zero", 0, 0, false}, {"equal", 4, 4, false}, {"source", 4, 0, false},
				{"target", 0, 6, false}, {"both", 4, 6, false}, {"unaligned", 3, 5, false},
				{"extend", 8, 16, false}, {"append_equal", 16, 16, true}, {"append_different", 0, 16, true},
			} {
				t.Run(fmt.Sprintf("readFrom_%t_%s", readFrom, tc.name), func(t *testing.T) {
					name := pathpkg.Join(dir, fmt.Sprintf("dest-%t-%s", readFrom, tc.name))
					require.NoError(t, e.fs.WriteFile(ctx, name, []byte(destinationText), 0600))
					src, err := e.fs.Open(ctx, source)
					require.NoError(t, err)
					defer src.Close(context.Background())
					flags := os.O_RDWR
					if tc.appendMode {
						flags |= os.O_APPEND
					}
					dst, err := e.fs.OpenFile(ctx, name, flags, 0600)
					require.NoError(t, err)
					defer dst.Close(context.Background())
					_, err = src.Seek(ctx, tc.source, io.SeekStart)
					require.NoError(t, err)
					if !tc.appendMode {
						_, err = dst.Seek(ctx, tc.target, io.SeekStart)
						require.NoError(t, err)
					}
					var n int64
					if readFrom {
						n, err = dst.ReadFrom(ctx, src.WithContext(ctx))
					} else {
						n, err = src.WriteTo(ctx, dst.WithContext(ctx))
					}
					require.NoError(t, err)
					require.Equal(t, int64(len(sourceText))-tc.source, n)
					require.NoError(t, dst.Close(ctx))
					actual, err := e.fs.ReadFile(ctx, name)
					require.NoError(t, err)
					end := int(tc.target + n)
					expected := []byte(destinationText)
					if end > len(expected) {
						expected = append(expected, make([]byte, end-len(expected))...)
					}
					copy(expected[tc.target:], sourceText[tc.source:])
					require.Equal(t, string(expected), string(actual))
				})
			}
		}
	})
}
