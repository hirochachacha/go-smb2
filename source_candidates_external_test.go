package smb2_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func TestSourceCandidateColdDFSRename(t *testing.T) {
	for _, tc := range []struct {
		name                                              string
		warmSource, warmDestination, samePrefix, distinct bool
	}{
		{name: "both-cold"}, {name: "cold-source-warm-destination", warmDestination: true},
		{name: "warm-source", warmSource: true}, {name: "same-prefix", samePrefix: true},
		{name: "distinct-shares", warmSource: true, distinct: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := newDFSExternalEndpoint("namespace-server")
			ns.caps["namespace"] = true
			ns.create = func(path string, _ wire.PacketCodec) (erref.NtStatus, uint32) {
				lower := strings.ToLower(path)
				if strings.Contains(lower, `\namespace\left`) || strings.Contains(lower, `\namespace\right`) {
					return erref.STATUS_PATH_NOT_COVERED, 0
				}
				return erref.STATUS_SUCCESS, 0
			}
			ns.referral = func(path string) []byte {
				lower := strings.ToLower(path)
				for _, alias := range []string{"left", "right"} {
					prefix := `\namespace-server\namespace\` + alias
					if strings.HasPrefix(lower, prefix) {
						share := "storage"
						if tc.distinct && alias == "right" {
							share = "other"
						}
						return externalDFSReferralV3(prefix, `\\target-server\`+share+`\base`)
					}
				}
				return nil
			}
			target := newDFSExternalEndpoint("target-server")
			// The seeded source exists before constructing the tested Client. This
			// fixture counts mutations only; it does not pretend to mutate contents.
			target.create = func(path string, p wire.PacketCodec) (erref.NtStatus, uint32) {
				if strings.HasSuffix(strings.ToLower(path), `\destination`) {
					return erref.STATUS_OBJECT_NAME_NOT_FOUND, 0
				}
				return erref.STATUS_SUCCESS, 0
			}
			client := newDFSExternalClient(t, ns, target)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			oldpath := `\\namespace-server\namespace\left\source`
			destAlias := "right"
			if tc.samePrefix {
				destAlias = "left"
			}
			newpath := `\\namespace-server\namespace\` + destAlias + `\destination`
			warm := func(path string) {
				f, err := client.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err = f.Close(cleanup); err != nil {
					t.Fatal(err)
				}
			}
			if tc.warmSource {
				warm(oldpath)
			}
			if tc.warmDestination {
				warm(`\\namespace-server\namespace\right\seed`)
			}
			err := client.Rename(ctx, oldpath, newpath)
			target.mu.Lock()
			mutations := target.mutations
			details := append([]dfsExternalCreate(nil), target.createDetails...)
			names := append([]string(nil), target.setInfoNames...)
			target.mu.Unlock()
			ns.mu.Lock()
			queries := append([]string(nil), ns.referralQueries...)
			nsMutations := ns.mutations
			ns.mu.Unlock()
			t.Logf("Rename=%v; namespace referrals=%q; target mutations=%d; destination names=%q", err, queries, mutations, names)
			if tc.distinct {
				if err == nil || mutations != 0 || nsMutations != 0 {
					t.Errorf("distinct shares must reject without mutations: %v,%d,%d", err, mutations, nsMutations)
				}
				return
			}
			if err != nil {
				t.Errorf("same storage/base Rename: %v", err)
			} else if mutations != 1 {
				t.Errorf("mutations=%d; want 1", mutations)
			}
			for _, detail := range details {
				if detail.access&wire.DELETE != 0 && detail.options&wire.FILE_OPEN_REPARSE_POINT == 0 {
					t.Errorf("final source link would be followed: %+v", detail)
				}
			}
			if !tc.warmSource && !tc.samePrefix {
				for _, query := range queries {
					if strings.Contains(strings.ToLower(query), `\left`) {
						t.Logf("source discovery occurred: %s", query)
					}
				}
			}
			var link *os.LinkError
			if err != nil && !errors.As(err, &link) {
				t.Error(fmt.Sprintf("missing LinkError: %v", err))
			}
		})
	}
}
