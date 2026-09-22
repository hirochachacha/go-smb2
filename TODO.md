# TODO

Analysis of the codebase (2026-09-22): refactoring opportunities and security
findings. Severity: **high** / **medium** / **low** / **info**.

Verification status: `go build ./...`, `go vet ./...`, and
`go test -short ./...` pass. `staticcheck` could not run (binary built with
Go 1.26 vs module requiring Go 1.27). `-race` unavailable (CGO disabled).
Findings below were confirmed by reading the source.

---

## Security issues

### High

_None confirmed._

### Medium

1. **Unsigned responses accepted when signing is optional**
   - `x/protocol/conn.go:1281-1290` (`tryVerify`), `x/protocol/dialer.go:230`
   - If `RequireMessageSigning` is false (the default) and the server only
     advertises signing as *enabled* (not *required*), responses without
     `SMB2_FLAGS_SIGNED` are accepted without verification. On a cleartext
     transport an active MITM can inject or modify unsigned traffic.
   - Fix: document clearly (README already shows
     `RequireMessageSigning: true` only in one example) that signing should
     be required for non-secure transports; consider defaulting
     `RequireMessageSigning` to true, or at least logging/warning when
     signing ends up disabled over plain TCP.

2. **Panic in client session/share creation crashes the process**
   - `client/connections.go:102-106`
   - The creation goroutine recovers a panic only to record it, then
     re-panics (`panic(r)`) in a background goroutine, which terminates the
     whole process. AGENTS.md: public APIs must not panic (except nil ctx /
     `MustXXX`). An internal bug in `Dial`/`Mount` therefore becomes a
     process-wide crash rather than an error to waiters.
   - Fix: do not re-panic after `finishCreation` has published the error;
     keep the recovery so concurrent waiters observe the failure.

3. **Protocol error types leak through the public API boundary**
   - `client/referrals.go:342,532,543` unwraps `*protocol.TransportError`,
     `*protocol.CrossShareSymlinkError`, `*protocol.DFSReferralRequiredError`;
     external tests assert them from `Client.Open`
     (`api_external_test.go:374,479`). Root package also returns
     `*protocol.ResponseError` / `*protocol.CompoundResponseError` through
     `Share`/`File` (e.g. inspected via `protocol.ResponseErrorAt` at
     `share.go:411`).
   - AGENTS.md forbids returning `protocol` types outside `x/protocol`
     (except `Share.Request`). If error values are intentionally exempt,
     amend AGENTS.md; otherwise define public error types in the root /
     `client` packages and map at the boundary.
   - Fix: decide policy, then either wrap or document the exemption.

### Low

4. **Committed CI credential in repository**
   - `.github/client_conf.json` contains `"user": "runner"`,
     `"passwd": "Passwd123!"` and is tracked by git.
   - It is a localhost Samba CI fixture, but it is a plaintext password in
     the repo (policy: never commit secrets/keys).
   - Fix: inject via CI secret/environment variable instead of a tracked
     file, or clearly document it as a non-secret throwaway CI password in
     the file itself.

5. **`os.Is*` usage violates project policy**
   - `smb2_test.go:706,720,732,739,746,781` use `os.IsTimeout` /
     `os.IsExist`. Policy requires `errors.Is` (or `errors.Is(err,
     os.ErrDeadlineExceeded)` / `os.ErrExist`).
   - Fix: replace with `errors.Is` equivalents.

6. **Re-panic paths outside `MustXXX` / nil-ctx conventions**
   - `internal/msrpc/srvsvc.go:64` panics when fragment length exceeds
     uint16 (encode-side argument validation; reachable only via internal
     callers — acceptable but worth an error return for symmetry).
   - `internal/crypto/cmac/cmac.go:65` panics on invalid block size
     (inherited x/crypto style; has a pre-existing `TODO` at line 52).
   - `client/connections.go:105` — see medium #2.
   - All other `panic("nil context")` sites match the allowed convention.

### Info (hardening notes, no defect found)

7. **Wire decoding looks solid**: `x/wire` decoders consistently validate in
   `IsInvalid()` before getters (contract in `x/wire/AGENTS.md`);
   `FileNotifyInformationDecoder.IsInvalid` (`x/wire/fscc.go:608-647`)
   checks lengths, alignment, padding, and action range. NTLM challenge
   parsing (`internal/ntlm/challengemessage.go:18-91`) and DFS referral
   parsing (`internal/dfsc/dfsc.go:171-259`) bound-check offsets with
   `uint64` arithmetic. NDR decoder (`internal/msrpc/ndr.go`) rejects
   non-zero offsets, count mismatches, and oversized strings.
8. **Signature verification** uses `subtle.ConstantTimeCompare`
   (`x/protocol/session.go:541`); encryption nonces come from `crypto/rand`
   (`x/protocol/session.go:556`); CCM tag compare is constant-time
   (`internal/crypto/ccm/ccm.go:132`).
9. **Context cancellation** does not close shared connections for ordinary
   requests (`x/protocol/conn.go:700-713` sends `SMB2 CANCEL` only).
   `Dial`'s transport watcher is carefully joined before ownership transfer
   (`x/protocol/dialer.go:117-142`); `Session.Close`'s forced close
   (`x/protocol/session.go:79`) is owner-initiated, not request cancellation.
10. **Secrets hygiene**: local `.env` and `client_conf.json` are gitignored
    (`.gitignore:36,39`); `testdata/local/` holds only local test certs.
11. **Receiver panic containment**: `runReceiver` recovers and shuts the
    connection down with an error (`x/protocol/conn.go:773-779`).

---

## Refactoring opportunities

Prioritized; each item is independently shippable.

### P1 — high value

1. **Consolidate test fake-server harness** (~1500 duplicated lines)
   - Generic helpers already exist: `sendCompoundResponse`
     (`protocol_fixture_test.go:236`), `testWriteResponse`
     (`protocol_fixture_test.go:216`), yet the encode → set
     MessageId/SessionId/TreeId/Status → pad → `SetNextCommand` loop is
     hand-rolled ~14 times (`session_test.go` 9×, `file_test.go` 3×,
     `share_test.go` 2×; `share_test.go:231 sendTestCompoundErrorResponse`
     reimplements it again).
   - Two competing full fake servers in the same package:
     `share_test.go:3796 fakeServerFull` vs `file_test.go:168
     startFullFakeServer`.
   - The 12 `TestListShareNames_*` tests (`session_test.go:36-1810`, each
     100–200 lines) rebuild the same server loop — convert to one harness +
     table-driven test.
   - Also: `file_test.go:490 sendTestResponse` ≈
     `protocol_fixture_test.go:216 testWriteResponse`.

2. **Split `share.go` (1878 lines, 60 funcs)**
   - Seams: FS namespace ops (~111–970), COPYCHUNK copy (`copyFile`
     973–1153), IO pipeline (1155–1527), MkdirAll/RemoveAll (1530–1730),
     security descriptors (1772–1878).
   - Suggested files: `share.go` (lifecycle/open), `share_io.go`,
     `share_copy.go`, `share_security.go`.

3. **Dedupe root ↔ `x/protocol` Dialer**
   - Fields mirrored by hand: `dialer.go:38-64` vs
     `x/protocol/dialer.go:39-61`, copied field-by-field at
     `dialer.go:96-104`.
   - Constants `Dialect`/`SMB202…` and `Cipher`/`AES128…` duplicated at
     `dialer.go:14-33` vs `x/protocol/dialer.go:16-35` (both already alias
     `wire` types — one definition suffices).

4. **Resolve protocol-error boundary policy** (security #3 above) — either
   wrap errors in public types or amend AGENTS.md.

### P2 — medium value

5. **Extract repeated Share path-normalization prologue**
   - `pathpkg.NormalizeRelPath(pathpkg.ToSMBPath(x))` appears ~20× in
     `share.go` (e.g. 136, 202, 219, 256, 297, 337, 394, 500, 545, 557,
     569, 752, 765, 858, 901, 1532, 1602, 1785, 1841).
   - Add `normalizeName(name string) (string, error)` in the root package.

6. **Introduce `pathErr` helper for `os.PathError`**
   - Constructed inline ~81× (`file.go` 20×, `share.go` ~30×,
     `session.go` 10×). `client/fs.go:43 fsError` and `fs.go:26
     contextPathError` already show the right shape; adopt one helper in
     the root package. Also unify `client/operations.go:82,89,93,141,161,313`
     and `client/referrals.go:50,54`, which build `os.PathError` manually
     despite `fsError` existing (inconsistent use of
     `unwrapFilesystemError`, e.g. `operations.go:82` vs `:93`).

7. **Move Symlink target classification into `internal/path`**
   - `share.go:344-367` hand-parses `'\\'`, `':'`, `` `\??\` ``, `` `\\` ``
     literals. Related helpers already exist: `internal/path/symlink.go`
     (`SplitSymlinkUNC`, `NormalizeSymlinkUNC`), `x/wire/dtyp.go:238-266`
     (`TrimUNCPrefix`, `HasUNCPrefix`).
   - Extract e.g. `ClassifySymlinkTarget(target) (kind, substitute, print)`.

8. **Deduplicate DFS path normalization**
   - `internal/dfsc/dfsc.go:42-51` and `:75-84` — `normalizedPath` method
     bodies are character-identical; extract a free function. Leading
     backslash munging at `dfsc.go:47-50, 80-83, 283, 298` duplicates
     concerns that AGENTS.md assigns to `internal/path` — consider
     `NormalizeDFSPath` there.

9. **`canonicalKey` builds keys with a raw separator**
   - `client/client.go:93-98` uses `strings.Join(parts, "\\")` for
     session/share cache keys. Either use `pathpkg.Join` or document that
     this is a map key, not a path (and that `\` cannot appear in
     server/share names — `ValidShareName`/`SplitUNC` already reject it for
     UNC inputs).

10. **Deduplicate `truncate`/`chtimes`/`chmod` skeletons**
    - `share.go:608-631`, `share.go:634-666`, `share.go:668+` share the
      same “build request → WithFileID or Create → SetInfo → Do → Close”
      shape; extract a `setInfoByPathOrFD` helper.

11. **Parallel read/write pipeline scaffolding**
    - `readAt`/`writeAt` (`share.go:1358-1411`, `1468-1516`),
      `readAtSequential`/`writeAtSequential` (`1413`, `1518`),
      `readAtChunk`/`writeAtChunk` (`1155`, `1192`) share structure; a
      single generic driver over a request/response strategy would collapse
      them.

12. **Centralize wire request type-switches**
    - Four parallel switches over `*wire.QueryInfoRequest` /
      `*wire.WriteRequest` / `*wire.IoctlRequest` etc.:
      `x/protocol/credit.go:126-183`, `payload.go:27-46`,
      `compound.go:93-118`, `tree_conn.go:255-265` (plus expected-read
      re-switch in `conn.go:529-538`). A single `requestTraits(req)`
      descriptor would centralize payload-size / max-output / expected-I/O
      logic.

13. **Negotiate context validation loop**
    - `x/protocol/dialer.go:246-375`: each context branch repeats
      `IsInvalid` → count checks → `invalidResponse` → duplicate-flag
      bookkeeping (77 `invalidResponse` calls package-wide). A small
      `validateOnce(seen *bool, nc, name)` helper would shrink `negotiate`.

### P3 — lower value / polish

14. **Split oversized `x/` and protocol files**
    - `x/wire/request.go` (1995), `x/wire/response.go` (1941) — split by
      domain (negotiate/session, tree/file, info/directory,
      ioctl/security), keeping request/response pairs together.
    - `x/wire/fscc.go` (1383) — split by FSCTL/information family.
    - `x/protocol/conn.go` (1392) — outstanding-request registry, send
      path, receiver, lifecycle → four files.
    - `x/protocol/dialer.go` — move SMB 3.1.1 negotiate-context parsing
      (246–382) to `negotiate.go`.

15. **Decompose long production functions**
    | Lines | Function |
    |-------|----------|
    | 231 | `(*conn).makeOutstandingRequest` — `x/protocol/conn.go:435` (direct-write, span calc, rr construction, encode, sign, compress/encrypt are extractable phases) |
    | 215 | `(*Dialer).negotiate` — `x/protocol/dialer.go:168` |
    | 214 | `(*ntlm.Client).Authenticate` — `internal/ntlm/client.go` |
    | 205 | `(*ntlm.Server).Authenticate` — `internal/ntlm/server.go` |
    | 200 | `(*account).loan` — `x/protocol/credit.go:116` (clean split at ~194: charge computation vs wait/assign) |
    | 181 | `(*Share).copyFile` — `share.go:973` |
    | 131 | `sddlSID` — `security/sddl.go`; `NetShareEnumAllResponseDecoder.ShareInfos` — `internal/msrpc/srvsvc.go` |
    | 128 | `(*session).setupKeys` — `x/protocol/session.go:201` |
    | 100 | `(*conn).runReceiver` — `x/protocol/conn.go:779` |

16. **Remove dead code** (verified with staticcheck U1000 intent + manual)
    - `x/protocol/limit.go:12 maxDFSReferralResponseSize` — unused
      duplicate of root `limit.go:6`.
    - `x/protocol/session.go:404 (*session).broken` — no callers.
    - `x/protocol/dialer.go:237-239` — commented-out dead lines.
    - Test-only: `auth/initiator_test.go:76`, `session_test.go:1812
      makeDFSReferralV3`, `share_test.go:2273 encodeSymlinkErrorResponse`
      (100+ lines), `x/protocol/session_test.go:362`.
    - `share_test.go:226 newTestShare` — trivial alias of
      `newProtocolTestShare`.

17. **Add `// Code generated ... DO NOT EDIT.` marker to
    `internal/erref/ntstatus.go`**
    - Generated by `mkntstatus.go` (`go:generate` in `erref.go`) but lacks
      the marker, so linters treat 3598 lines as hand-written (staticcheck
      ST1003 floods on `STATUS_*` names).

18. **Test file organization**
    - Oversized: `share_test.go` (~6600 lines), `file_test.go` (~4700),
      `x/protocol/conn_test.go` (~4700), `smb2_test.go` (~2900),
      `dfs_external_test.go` (~2050), `session_test.go` (~1870).
    - Split `share_test.go` by domain (create/open, RW pipeline, copy,
      security, symlink/rename) with shared helpers in
      `share_testutil_test.go`.
    - Long test functions (>150 lines) mostly collapse under P1 item 1.

19. **Naming consistency**
    - Receiver names in `session.go` mix `c` and `s`
      (`GetDFSReferrals` uses `s` at `session.go:216`; 8 other methods use
      `c`) — staticcheck ST1016.
    - io/fs adapters: `boundShare`/`boundFile` (root `fs.go:16,158`) vs
      `boundClient`/`boundClientFile` (`client/fs.go:37,305`).
    - `client/operations.go` (336 lines of file ops) — vague name; domain
      name preferred (`file.go`/`fsops.go`).
    - Fake-server names: `fakeServerFull` vs `startFullFakeServer` vs
      `fakeServer`.
    - `FileDescriptor.FileId`/`VolumeId` (`file.go:296,300`),
      `Dialer.ClientGuid` (`dialer.go:52`) — wire-style `Id`/`Guid` in
      Go-facing API (staticcheck ST1003); renaming is an API break, decide
      deliberately (compatibility is not a default requirement).

20. **Missing package docs** (8 packages): `x/wire`,
    `internal/{ccm,cmac,dfsc,erref,ntlm,spnego,utf16le}`. `x/wire`'s
    contract lives in `x/wire/AGENTS.md` — a short package comment
    pointing there would help `go doc` users.

21. **Existing in-source TODOs** (only two in the library):
    - `internal/ntlm/session.go:48` — `// TODO export to somewhere`
      (`Session.InfoMap`).
    - `internal/crypto/cmac/cmac.go:52` — inherited
      `TODO(rsc): panic vs error` in `New`.

---

## Explicit non-findings

- No import cycles; layering `client` → root → `x/protocol` → `x/wire` is
  clean.
- No `utils`/`helpers`/`misc` directories; layout is domain-based.
- `go test -short ./...` passes across all packages.
- Request cancellation correctly avoids closing shared resources
  (AGENTS.md lifecycle rules hold in `recv`/`sendCancel`).
