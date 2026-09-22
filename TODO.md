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

- [ ] **P2 — Complete append write semantics after real-server reproduction.**
  `TestAppendIntegration` now reproduces the remaining failures with the current
  client_conf.json: 8 ordinary configurations connected (1 Windows, 1 macOS,
  6 Samba transport/auth/share configurations); 1 further ordinary connection
  was refused. The 2 specialized DFS/Kerberos matrix entries were not selected.
  All 8 connected configurations failed append after Seek, with and without
  O_TRUNC, concurrent append through four handles, and ReadFrom/WriteTo append
  copies. Large single-handle writes passed on 7; macOS returned access denied.
  Control tests TestFile and TestServerSideCopy passed on all 8 configurations;
  these failures are specific to append paths. No cleanup failures were reported.
  Test files live in unique directories and are removed by test cleanup.

  OpenFile retains GENERIC_WRITE for O_APPEND|O_TRUNC. Simply removing that
  right is insufficient: MS-FSA 2.1.5.1.2 can grant FILE_WRITE_DATA implicitly
  during overwrite creation. A separate low-level probe of WRITE Offset
  0xffffffffffffffff with a read/write handle was rejected by all 8 connected
  configurations with STATUS_INVALID_PARAMETER. The negative-offset behavior
  of the MS-FSA object store cannot be assumed to be exposed by these SMB servers.
  Querying EOF before writing would still race with other writers.

  Runtime behavior is unchanged pending a correct append strategy. Resolve
  server-enforced atomicity, chunk ordering, offset updates, and the positional
  server-side copy optimization before considering this fixed. The new
  integration regression test intentionally remains failing for the known bug:
  `go test -run '^TestAppendIntegration$' -count=1 -timeout=5m .`.
  Ordinary unit tests still skip network tests with `-short`.

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
