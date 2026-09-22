# Review TODOs

Reviewed 2026-09-22 at `054030f9ec08f27b7755f8bdcbc04a7107761e9f`.
Priorities indicate implementation order, not vulnerability severity.
This is a source review of the principal runtime paths, with selected local
reproductions; it is not an exhaustive audit of every file or dependency.

## Security and untrusted-input validation

- [x] **P1 — Validate asynchronous interim responses before updating request state.**
  In `x/protocol/conn.go:1318`, `STATUS_PENDING` grants credits and can overwrite
  `rr.asyncId` without checking the original command, the required async flag,
  a nonzero/stable async identifier, or the zero-data SMB2 ERROR envelope.
  A malformed server response can corrupt request tracking, misdirect CANCEL,
  or make a subsequent final response fail the check in
  `x/protocol/tree_conn.go:327`. Validate before mutating credits or request state,
  following MS-SMB2 3.3.4.2. Add cases for wrong command, missing/truncated body,
  missing async flag, zero ID, and replacement of an established ID.
  **Severity: low; statically confirmed.** The signature exemption for pending
  replies is required by the protocol and must remain. These checks do not
  authenticate interim replies; encrypted requests already reject plaintext.

- [x] **P1 — Validate recognized ACE bodies even when preserving them as raw bytes.**
  `security/security.go:590` validates only selected structured ACE types;
  the default at line 601 preserves other known types in `Raw`, and
  `ACE.validate` checks only their header/size/revision/placement. A four-byte
  `ACCESS_ALLOWED_OBJECT_ACE` (`05 00 04 00`) is accepted despite lacking its
  mandatory Mask, Flags, and SID (MS-DTYP 2.4.4.3).
  This reaches `Share.GetSecurityDescriptor` through
  `x/protocol/payload.go:83`, which promises validated output.
  Add decoding-specific body checks for recognized layouts, including optional
  GUID boundaries and SID validity; retain raw representation where appropriate.
  Regression input to `security.DecodeDescriptor`:
  `010004800000000000000000000000001400000004000c000100000005000400`.
  **Severity: low; locally reproduced as accepted with no error.** No access-control
  bypass or memory corruption was demonstrated. Test both rejection of this
  descriptor and acceptance of complete object ACEs.
  Completed: object/callback SID and GUID checks, plus resource attribute
  Mask/Everyone SID and claim offset/type/value validation. Unknown ACEs and
  callback application data remain opaque; conditional-expression validation
  (MS-DTYP 2.4.4.17) is not covered by this fix.

- [x] **P1 — Enforce requested QUERY_INFO and QUERY_DIRECTORY output limits.**
  `x/protocol/payload.go:29` drops these requests' `OutputBufferLength` when
  snapshotting request metadata. `validateRequestedOutput` in
  `x/protocol/response_validation.go:31` checks IOCTL and CHANGE_NOTIFY, but
  not these queries. A server can return a structurally valid oversized payload
  and trigger more decoding/result allocation than requested. Retain the limits
  and reject oversized success or applicable partial-output responses before
  exposing payloads. Cover both commands and their relevant status codes.
  **Severity: low; statically confirmed.** The existing `0xffffff` frame and
  decompression limits bound individual messages; no out-of-bounds write was
  established. This fix limits downstream processing, not initial frame allocation.

## Correctness and API robustness

- [x] **P1 — Reject unusable I/O pipeline depths during Dial.**
  `x/protocol/dialer.go:166` stores arbitrary `IOPipelineDepth` values, and
  `x/protocol/tree_conn.go:125` returns them unchanged. The first sufficiently
  large disk I/O passes that uint directly to channel allocation in
  `share.go:1259`. Values such as `^uint(0)` cannot be valid channel capacities
  and will panic instead of producing a Dial configuration error.
  Validate the setting before publishing the session and avoid allocating queues
  larger than the operation needs. Test extreme values without making huge
  allocations. This is a caller-configuration defect; remote exploitability
  was not established.

- [x] **P2 — Close concrete gaps in the public no-panic contract.**
  `(&security.ACE{}).Encode(nil)` panics at `security/security.go:325` because
  `Size()` returns zero and the buffer check passes; encoding an ACL containing
  that ACE into its advertised size also panics. A nil `*Share` panics in
  `Unmount` at `share.go:115`. Both cases were locally reproduced.
  Also guard a typed-nil `*protocol.ResponseError` in
  `x/protocol/errors.go:272` before dereferencing it in `BufferOverflowData`.
  That panic was also locally reproduced.
  Add narrow input/receiver checks and regression cases; no broad recovery layer
  is needed. `Descriptor.Encode` already rejects invalid structured ACEs.
  Completed: guarded these inputs. `MustSID`/`MustDescriptor` remain intentional
  panic-on-error APIs; AGENTS.md now explicitly permits `MustXXX` panics.

- [x] **P2 — Reject WriteAt on append-opened files.**
  Store append mode in core File and reject WriteAt, including zero-length
  writes, before sending any request. Tests cover core File, client File,
  and both context adapters, including O_APPEND|O_TRUNC in the core API.

- [x] **P2 — Define the append guarantee and align integration tests.**
  Atomic append across independently opened handles, sessions, or clients is
  outside the supported contract. Applications coordinate multiple writers;
  do not introduce implicit SMB locking solely for cross-handle atomicity.
  AGENTS.md and README.md document this boundary. Also, os.File explicitly
  leaves Seek on O_APPEND files unspecified; the earlier review overstated
  Seek-after-append behavior as a required compatibility guarantee.
  TestAppendIntegration no longer asserts concurrent-handle or Seek behavior.
  It covers one destination writer, sequential writes with/without O_TRUNC,
  large writes, and ReadFrom/WriteTo copies without Seek.

- [x] **P2 — Investigate and fix macOS single-writer append failures.**
  Direct request probes separated three causes:
  - WRITE with access 0x80120114 (append data, no write data) returned access
    denied; adding FILE_WRITE_DATA (0x80120116) succeeded. OpenFile now retains
    normal write access for append rather than requesting an append-only handle.
  - After overwrite creation, CREATE reported EndofFile=3 while QUERY_INFO on
    the same handle reported 0. Initialize truncated append handles at zero
    instead of using the stale CREATE size.
  - Without FILE_WRITE_DATA, COPYCHUNK returned success with all response
    counters zero and left the destination unchanged. Adding write data access
    yielded a successful count but copied at the wrong target offset (below).
    Initially excluded append destinations from server-side copy; the final
    policy below instead compares source and destination offsets. Neither
    retries nor relaxed response validation are used.

  Regression tests cover stale CREATE sizes and both append copy entry points,
  including write offsets and resulting file positions. Live macOS append tests
  now pass all five cases. Final `go test -short ./...` passed. Live append,
  TestFile, and TestServerSideCopy passed on macOS, Windows (after a connection
  timeout and retry), and six Samba configurations. One other ordinary
  connection was refused; specialized DFS/Kerberos matrices were not selected.
  No test-directory cleanup failures were reported.
  No implicit locks or per-write size queries were
  added. Append opens require ordinary write permission; append-only ACL access
  is not supported by this strategy. Copy dispatch follows the offset policy
  below, including append destinations.

- [x] **P2 — Address macOS COPYCHUNK destination-offset corruption.**
  Expanded investigation confirms that SourceOffset and Length are honored,
  but the tested macOS server writes at SourceOffset in the destination rather
  than at TargetOffset. With source "AAAABBBBCCCC", destination
  "0123456789abcdef", SourceOffset=4, TargetOffset=0, Length=4, it returns
  success and four bytes copied but produces "0123BBBB89abcdef", not
  "BBBB456789abcdef". Nonaligned and multiple-chunk cases reproduce the same
  behavior; equal source/target offsets pass. The earlier zero-offset write
  observation was the special case SourceOffset=0.
  TestServerSideCopyOffsets records encoded chunks, response counts, and actual
  contents. COPYCHUNK_WRITE is explicitly unsupported on this macOS server.
  Completed: Share.copyFile declines unequal offsets before sending requests;
  File.ReadFrom/WriteTo then use ordinary reads/writes. The decision is made
  while the existing file-pair mutexes protect both positions. Equal offsets
  retain server-side copy for both ordinary and append destinations.
  Regression tests verify contents, positions, and READ/WRITE versus COPYCHUNK
  dispatch through ReadFrom, WriteTo, and io.Copy. Equal offsets near MaxInt64
  still have bounded chunks. TestFileCopyOffsets exercises the File API on live
  servers; the raw TestServerSideCopyOffsets remains an intentional server-bug
  reproducer and still fails on macOS when requesting unequal offsets directly.
  Final verification: go test -short ./... passed; TestFileCopyOffsets,
  TestAppendIntegration, and TestServerSideCopy passed on all eight reachable
  configurations. One configured connection was refused. Cleanup succeeded.
  Server: macOS 26.6.2 (25G83). Windows and
  six Samba configurations passed all nine cases for both copy controls;
  macOS failed the six COPYCHUNK cases with unequal offsets.
  See [COPYCHUNK_REPRO.md](COPYCHUNK_REPRO.md) for the unsent Apple report draft.

## Refactoring opportunities

- [x] **P2 — Finish consolidating path operations in `internal/path`.**
  Replace separator-based parent extraction in `client/client.go:481`, UNC
  normalization/suffix joining in `session.go:289`, and duplicate UNC/symlink
  parsing in `x/protocol/symlink.go` with purpose-specific path operations.
  `client/fs.go` also performs joins/splits outside the designated package.
  Preserve the distinction between SMB paths, public UNC paths, DFS wire paths,
  and POSIX adapter paths. Verify existing DFS/symlink/path tests after moving
  logic; avoid silently changing normalization while consolidating it.

- [x] **P2 — Share the direct-read length check before either receive path writes.**
  `x/protocol/conn.go:910` checks both the registered buffer and requested READ
  length in `directReadSink`; `copyDecryptedReadPayload` at line 1217 checks only
  buffer size before copying. Later validation rejects excessive requested length,
  but the copy has already occurred. Use a shared length predicate before writing
  in both paths. Test a low-level direct READ whose buffer is larger than its
  requested length. Core file reads already register a buffer capped to the
  request; this is not an established write outside the borrowed buffer.

- [x] **P3 — Split `client/client.go` along its existing responsibilities.**
  Move session/share acquisition and teardown, DFS referral cache/routing, and
  filesystem operations into focused files in the same package. Keep the shared
  mutex and session-generation ownership explicit. The current file combines
  these responsibilities across roughly 1,300 lines; no new abstraction or public
  API is needed. Run the existing client and lifecycle tests after the move.

- [x] **P3 — Align README guarantees with the implementation.**
  `README.md:22` advertises cancellation across all operations, while
  `auth/kerberos.go:39` and `auth/kerberos.go:87` explicitly exclude KDC I/O.
  Document that dependency timeout and the intentional final-response waits for
  CREATE/LOCK (`x/protocol/conn.go:693`) alongside the general guarantee.
  Avoid implying that every deadline immediately returns control.
  Also update the advertised minimum Go version: `README.md:27` says Go 1.26,
  while `go.mod:3` requires Go 1.27.0.

## Verification and limits

`go test -short ./...` passed (cached results). A temporary standalone Go
program reproduced the malformed-descriptor acceptance and ACE/ACL/nil-Share
panics; a second reproduced the typed-nil error-helper panic. No reproduction
files were added to the repository. Other findings
above are based on source traces and, where applicable, local Microsoft specs.
No integration server, live interception, dependency advisory scan, or exhaustive
fuzz campaign was used. Signing/encryption verification and direct-read
cancellation protections were inspected; no authentication bypass was confirmed.
The review left runtime source unchanged; checked items above were subsequently fixed.
