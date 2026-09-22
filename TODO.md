# TODO

Reviewed against the source on 2026-09-22. Retained items address concrete
API contracts, project rules, or substantial test maintenance costs.

Internal consolidation is worthwhile when it removes substantial repeated
logic across many call sites without changing public API signatures, types,
or observable behavior. Prioritize the fake-server infrastructure below.

## Consolidate fake-server test infrastructure

- `protocol_fixture_test.go` already provides `testWriteResponse` and
  `sendCompoundResponse`, but `session_test.go`, `file_test.go`, and
  `share_test.go` repeat response encoding and compound assembly.
- Reuse those helpers for ordinary responses and consolidate the shared
  setup in `TestListShareNames_*`. Reconcile `startFullFakeServer` and
  `fakeServerFull` where their responsibilities overlap.
- Keep malformed-response construction explicit and retain each test's
  protocol assertions. The benefit is reducing duplicated fixture logic
  that must change together.

## Consolidate repeated filesystem API plumbing

- `share.go` repeats `NormalizeRelPath(ToSMBPath(...))` at 20 call sites.
  Introduce a private helper for this boundary operation, preserving the
  explicit conversion order and each caller's error handling.
- `file.go`, `share.go`, and `session.go` contain 72 inline `os.PathError`
  constructions; `client/operations.go` and `client/referrals.go` add eight.
  Consolidate repeated construction with small private helpers and reuse
  `client.fsError` where its semantics match.
- Preserve operation names, reported paths, error chains, and nil handling.
  `contextPathError` and `unwrapFilesystemError` have different behavior;
  do not merge them merely because both handle path errors.

## Move symlink target path handling into `internal/path`

- `Share.Symlink` in `share.go` directly classifies drive, UNC, rooted,
  and relative targets and constructs substitute/print names.
- Move that path logic into `internal/path`, alongside the existing
  symlink helpers, as required by the project's path ownership rule.
  Keep request construction in `Share.Symlink` and preserve the existing
  target semantics and coverage.

## Centralize DFS path normalization

- `ReferralRequest.normalizedPath`, `ReferralRequestEx.normalizedPath`,
  and `normalizeDFSPath` in `internal/dfsc/dfsc.go` repeat the same
  leading-separator normalization.
- Move the shared path operation into `internal/path` and use it at
  those call sites. Preserve empty-input behavior and the distinction
  between DFS request paths and user-visible UNC paths.

## Replace remaining `os.Is*` test assertions

- `smb2_test.go` still uses `os.IsTimeout` and `os.IsExist`, contrary to
  project policy.
- Use `errors.Is` with the error expected by each scenario. In particular,
  the expired-context case must check `context.DeadlineExceeded`, not
  `os.ErrDeadlineExceeded`; the existence checks use `os.ErrExist`.
