package smb2_test

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"testing"
)

// TestMultiCreditIO exercises request sizes around the 64 KiB credit boundary so
// that the per-request CreditCharge and MessageId accounting are validated on a
// real server, including dialects that support multi-credit operations.
func TestMultiCreditIO(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestMultiCreditIO", os.Getpid())
		if err := fs.Mkdir(testDir, 0o755); err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(testDir)

		sizes := []int{
			0,
			1,
			64*1024 - 1,
			64 * 1024,
			64*1024 + 1,
			1024 * 1024,
			1024*1024 + 1,
		}

		for _, size := range sizes {
			name := join(testDir, fmt.Sprintf("bulk-%d.bin", size))

			data := make([]byte, size)
			for i := range data {
				data[i] = byte((i*31 + 7) % 251)
			}

			if err := fs.WriteFile(name, data, 0o644); err != nil {
				t.Fatalf("WriteFile(%d bytes): %v", size, err)
			}

			fi, err := fs.Stat(name)
			if err != nil {
				t.Fatalf("Stat(%d bytes): %v", size, err)
			}
			if fi.Size() != int64(size) {
				t.Fatalf("Stat(%d bytes) size = %d", size, fi.Size())
			}

			got, err := fs.ReadFile(name)
			if err != nil {
				t.Fatalf("ReadFile(%d bytes): %v", size, err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("ReadFile(%d bytes) returned %d bytes with different content", size, len(got))
			}

			if err := fs.Remove(name); err != nil {
				t.Fatalf("Remove(%d bytes): %v", size, err)
			}
		}
	})
}

// TestConcurrentShareAccess runs independent read/write cycles in parallel over
// one share so that credit lending, signing/encryption, and response dispatch
// are exercised concurrently rather than one request at a time.
func TestConcurrentShareAccess(t *testing.T) {
	forEachEnv(t, func(t *testing.T, e *env) {
		fs := e.fs
		testDir := fmt.Sprintf("testDir-%d-TestConcurrentShareAccess", os.Getpid())
		if err := fs.Mkdir(testDir, 0o755); err != nil {
			t.Fatal(err)
		}
		defer fs.RemoveAll(testDir)

		const (
			workers = 8
			size    = 128 * 1024
		)

		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()

				name := join(testDir, fmt.Sprintf("worker-%d.bin", w))
				data := make([]byte, size)
				for i := range data {
					data[i] = byte((i*17 + w*53) % 251)
				}

				if err := fs.WriteFile(name, data, 0o644); err != nil {
					errs <- fmt.Errorf("worker %d: WriteFile: %w", w, err)
					return
				}
				got, err := fs.ReadFile(name)
				if err != nil {
					errs <- fmt.Errorf("worker %d: ReadFile: %w", w, err)
					return
				}
				if !bytes.Equal(got, data) {
					errs <- fmt.Errorf("worker %d: content mismatch", w)
					return
				}
				if err := fs.Remove(name); err != nil {
					errs <- fmt.Errorf("worker %d: Remove: %w", w, err)
				}
			}(w)
		}

		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}
