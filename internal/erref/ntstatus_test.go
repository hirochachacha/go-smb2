package erref

import (
	"strings"
	"testing"
)

func TestUnknownNtStatusIncludesCode(t *testing.T) {
	t.Parallel()
	status := NtStatus(0xDEADBEEF)
	if message := status.Error(); !strings.Contains(message, "DEADBEEF") {
		t.Fatalf("unknown status message = %q, want numeric code", message)
	}
}
