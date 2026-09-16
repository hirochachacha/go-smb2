# DFS Implementation Status

**Implementation and local verification complete; real-environment verification incomplete.**

All phases, independent boundary reviews, the fresh final review, and fix rechecks are complete. No substantiated finding remains. No commit, push, PR, or publication was performed.

## Baseline

- Started 2026-09-15 on `master`, HEAD `7e88b3c8b4f7cde2be5441b0380b27bda5e4d9fc`.
- Initial working tree was clean, with no modified or untracked files.
- Baseline snapshot: `/tmp/go-smb2-dfs-baseline-4692sanq` (tracked and untracked file copies in `tree`, HEAD, branch, status, and diff).
- Task changes are measured against that snapshot. No commits or publication authorized.

## Phases

| Phase | State |
| --- | --- |
| Pre-implementation review | complete |
| 1. Dialer / Session / single tree | complete |
| 2. Referrals / symlinks / display names | complete |
| 3. DFS ownership / shutdown | complete |
| 4. Combined resolution / cache | complete |
| 5. Path operations / mutation boundaries | complete |
| 6. Migration / integrated verification | complete (local; real environment unverified) |

## Assignments

- Parent: integration, baseline, documents, API contracts, caller/test inventory.
- `pre_review` (GPT-5.6-luna, high): independent read-only pre-implementation review; no editable files.
- Future implementation and review assignments use GPT-5.6-luna, high as requested.

## Contracts and Evidence

- Public contracts are those in `DFS_DESIGN.md` and `DFS_IMPLEMENTATION_PLAN.md`, pending pre-review.
- Existing correction record is implementation plan section F.
- Applied `ms-specs` skill; local QMD index and specification corpus are available.
- MS-SMB2 3.2.5.5 specifies Capabilities.SMB2_SHARE_CAP_DFS for TreeConnect.IsDfsShare.

## Migration Inventory

- Existing Client API references occur in 12 Go files; primary areas: client/session, DFS resolver, unit tests, integration tests, README.
- Integration harness: `test/integration/run.sh`, Docker Compose Samba AD service, `smb2_test.go` loads `client_conf.json` and skips environment tests if absent.
- No existing `internal/smbpath` or implementation status file.

## Verification

- Baseline `go test ./... -timeout=120s`: passed (root package 25.840s; all packages passed).
- Real-environment verification unavailable: `docker` is not installed/on PATH, so the supplied Samba Compose harness cannot run. No external server configuration has been supplied.

## Findings

- PRE-001 (high): preserve DFS-link identity before Remove/Rename. Accepted; implementation requirement assigned to phases 4–5, including cached referrals and pinned mutations.
- PRE-002 (high): safe compound replay. Accepted; plan G clarifies typed errors certify CREATE stopped and later mutations unexecuted; no redundant public retry state. Independent recheck accepted contract, implementation pending.
- PRE-003 (medium/high): PathConsumed component boundary. Accepted; decoder fix assigned to lower owner.
- Shared-state recheck: canonicalize Enter inputs; pinned symlink returns ErrPathChanged without typed continuation/replay. Clarified plan G; no remaining pre-implementation blocker.

## Next Action

No implementation or local-verification work remains. Run the documented integration harness when Docker/Samba or a Windows server configuration is available; real-environment verification remains incomplete.

## Verification Map

- Lower ownership: independent concurrent Dial, configuration errors/defaults, dedicated IPC$ reuse, Close during Dial/auth/Mount, blocked-send shutdown and cancellation isolation.
- Lower wire/API: CAP_DFS versus ShareFlags, both CREATE paths, DOMAIN/DC request bytes, public referral fields, UTF-16 boundaries, same/cross-share symlinks, compound continuation safety, original versus actual path.
- Upper ownership: coalesced establishment, independently canceled waiters, retained intermediate sessions, Close races, failed-session generation invalidation.
- Upper resolution: ordinary share direct access, root/link/interlink transitions, longest component prefix, TTL/V1, target ordering/sets, conservative retries, shared traversal budget.
- Upper mutation boundaries: uncached/cached DFS links to subdirectories, share roots, ordinary children and final symlinks, both Rename endpoints, no replay after unknown mutation outcome.
- Final: external-package manual continuation/referrals/DFS File display, migrated examples/integration callers, gofmt, diff check, race suite, fresh independent review and fix rechecks.

## Current Handoff

- `lower_impl` (GPT-5.6-luna, high) owns lower SMB Go files, internal/dfsc decoder and necessary existing Go caller/test migration. Does not edit docs, dfs/, or internal/smbpath.
- Parent completed internal/smbpath and README migration draft. No shared-file edits with implementer.
- `go test ./internal/smbpath`: passed. Independent reviewer also ran `CGO_ENABLED=1 go test ./internal/smbpath -race`: passed.
- `pre_review` independently rechecked section G and shared-state implementation; no blocking contract finding remains. Lower behavior and phase-5 guards still need implementation verification.

- `external_tests` (GPT-5.6-luna, high) owns new `api_external_test.go` and optional `internal/smbtest/` simulator only. Verifies public manual continuation and referral retrieval independently of lower private fields; lower owner notified of scope separation.

## Upper-Layer Specification Notes

Parent read local MS-DFSC 3.1.5.1, 3.1.5.2, and 3.1.5.4.3 (QMD keyword searches returned no matches, so used section files):

- PATH_NOT_COVERED on a final link target must fail the original I/O. Root-target failure requires link identification and referral handling using the actual operation path.
- Other target errors permit, rather than require, candidate switching. The agreed conservative no-replay/authentication-failure policy is compatible with this choice.
- Refresh must preserve equivalent target lists/hints, including version-4 set equivalence, update TTL/failback/interlink state, reset missing hints, and apply failback from a later set to the first set when requested.
- Zero returned referrals fail the original operation with STATUS_OBJECT_PATH_NOT_FOUND.

## External API Milestone

- `external_tests` completed `api_external_test.go`: public Dial/Session/Mount, cross-share manual SymlinkError continuation, same-share symlink followed by DFSReferralError with changed Path, referral suffixes, DOMAIN/DC wire requests and name-list response fields.
- Agent command `go test api_external_test.go -run '^TestExternal' -count=20 -timeout=60s`: passed.
- Parent independently ran `go test api_external_test.go -run '^TestExternal' -timeout=60s`: passed; inspected source and output. These bypass currently unmigrated internal tests, so this is not a full-suite result.
- Five complete README Go examples parse successfully with gofmt; final type checking awaits integrated APIs.

## Ownership Split During Phase 1–2

- Parent rejected a newly added `legacy_test.go` test-only Client/ClientConfig compatibility implementation (MIG-001). It would test superseded behavior and violates the no-shim contract. Lower owner was paused and instructed to remove it and migrate tests to actual APIs.
- `lifecycle_impl` (GPT-5.6-luna, high) now exclusively owns client.go, session.go, conn.go, feature.go, transport.go, transport_dialer.go and corresponding client/session/connection/transport tests. Owns Dial shutdown, Session/IPC lifecycle, configuration docs, and lifecycle tests.
- `lower_impl` resumed with referral/error/path/request/share/tree/file/notify files and remaining caller/test migrations. No edits permitted to lifecycle-owned files, docs, internal/smbpath, or api_external_test.go.
- Parent continues integration and documentation; upper implementation remains gated on lower review.

## Integration Review Observations (Draft Code)

- LOW-001 (high): forced shutdown originally acquired the send mutex before transport Close. Corrected in draft to close first; lifecycle tests/review pending.
- LOW-002 (high): context timeout alone did not unblock IPC$/LOGOFF synchronous I/O. Draft adds independent deadline callback before IPC mutex wait; callback join reviewed separately and fix requested.
- LOW-003 (medium): public referral Prefix/TargetPath initially used single-backslash wire form and V1 zero-consumed conversion was faulty. Corrections requested; external basic referral tests pass, additional decoder cases pending.
- LOW-004 (high): continuationSafe accepted any nonnil later error, including transport ambiguity, and DFS continuation bypassed the guard. Corrections requested for both typed errors using MS-SMB2 3.3.5.2.7 related-operation rules; focused tests/review pending.
- MIG-001: prohibited test-only legacy API shim removed. Actual caller/test migration continues.

- Additional phase-2 test split: `external_tests` exclusively owns migration of `dfs_test.go` and new `lower_continuation_test.go`, alongside its completed external API tests. Adds CAP-versus-flags and compound continuation wire coverage; hands upper-specific old routing scenarios to parent. Lower implementer paused before reassignment, then resumed with these files excluded.

## Lifecycle First Handoff and Required Follow-up

- Agent snapshot `/tmp/go-smb2-life-pkdtEM/tree` excluded `dfs_test.go` and `share_enum_test.go` only in that disposable copy. Current integrated tree was not fully verified by these results.
- Snapshot focused normal command: `go test . -run 'Test(Dialer|Dial|SessionCloseConcurrent|ConnCloseClosesTransportOnce|ConnCloseUnblocksCreditLoan|ConnSendFailure)' -count=1 -timeout=120s`, passed 0.839s.
- Same selection with `CGO_ENABLED=1 go test -race`, passed 1.809s.
- Snapshot root suite passed 25.292s; snapshot root race suite passed about 56s. Excluded suites remain required.
- Parent rejected completion of required test coverage: independent Dials were only sequential; config test failed before normalization; no blocked-send-mutex Session.Close test; no cancel-after-publication test. Lifecycle owner assigned concrete meaningful tests for all four and cancellation isolation.
- Upper ownership handoff: replace old case-insensitive connection coalescing, retained sessions after unmount/canceled unmount, Close rejecting new connections, endpoint-specific credential/transport selection with dfs-owned scenarios. Baseline test source preserved in snapshot.

## Lower Wire Test Milestone

- `external_tests` migrated dfs_test.go, preserving makeDFSReferralV3 helper and replacing old resolver dependencies with CAP/flags, compound success/ambiguity, and pinned-path wire tests.
- Agent `go test ./... -run '^$' -count=1`: passed before concurrent lifecycle test edits.
- Agent `go test . -run 'Test(TreeCreateWirePathAndFlags|Compound|Pinned)' -count=20 -timeout=120s`: passed.
- A subsequent temporary client_test.go undefined `err` compile failure is from ongoing lifecycle test edits, not the clean baseline; owner notified.
- Upper test handoff from baseline dfs_test.go: cross-server referral routing, interlink traversal/cache, cross-share Rename rejection, File binding to target tree, and session retention after DFS tree disconnect. These must be implemented/tested in dfs before completion.

## Lower Integration Review

- Parent `go test ./... -run '^$'`: passed with all test files included.
- Parent `go test ./... -timeout=120s`: passed all included packages (cached).
- `lower_impl` completed/froze its scope; reports go build, full tests, focused API/DFS tests, internal tests, and diff check passed.
- Immutable review snapshot: `/tmp/go-smb2-lower-review-0s5i0f4j/tree`; tracked diff alongside at `tracked.patch`.
- `lower_review` (fresh GPT-5.6-luna, high) independently reviews phases 1–2 against the clean baseline and specifications. Lifecycle follow-up tests are outside this immutable snapshot; relevant later production fixes require re-review.

- Lower final snapshot correction: only share_io.go changed after review snapshot; exact final copy saved as `/tmp/go-smb2-lower-review-0s5i0f4j/share_io.final.go` and sent to reviewer (expanded rejection of local/device/relative-drive targets).
- Parent compiled all five complete README examples using `go test <example.go> -run '^$'`; all passed. Temporary files: `/tmp/go-smb2-readme-2hen1uvv`.
- LOW-005 (pending independent confirmation): old evalSymlinkError now has only test callers; new requestBuilder.resolveSymlink is the production evaluator. Existing Unicode/edge-case tests must migrate rather than only exercise unused old code.

- LOW-006 (high API integration defect, parent-confirmed): treeConn.fullPath returns the single-backslash DFS wire form and is used directly for public DFSReferralError.Path/SymlinkError.Path. Public contract requires full UNC; separate wire/public forms and assert exact error paths. Existing external suffix-only assertions missed this. Independent reviewer notified.
- LOW-007 (pending independent confirmation): decoded absolute symlink targets pass parseUNCPath without requiring a UNC prefix; validate continuation prefix/components and relative-flag consistency before issuing same-tree retries or public errors.

## Required Lifecycle Test Follow-up Complete

- Added successful concurrent independent Dials, config immutability through negotiation, cancel-after-Dial publication, blocked-send-mutex Session.Close deadline, and per-operation cancellation isolation.
- Current-worktree agent focused command `go test . -run 'Test(Dialer|Dial|SessionClose|CanceledOperation|ConnCloseClosesTransportOnce|ConnCloseUnblocksCreditLoan|ConnSendFailure)' -count=1 -timeout=180s`: passed 5.640s.
- Same selection with race and timeout 240s: passed 6.816s.
- Agent `go test ./... -count=1 -timeout=240s`: all included packages passed, root 30.656s.
- Agent `CGO_ENABLED=1 go test -race ./... -count=1 -timeout=300s`: all included packages passed, root 99.056s. Final workflow still requires final-code race command with timeout 120s after upper implementation.
- Final lifecycle test copies supplied to lower reviewer alongside snapshot as client.final_test.go and session.final_test.go.

- Parent independently ran the five required new lifecycle edge cases under `CGO_ENABLED=1 go test -race` with timeout 120s: passed 6.496s.
- `upper_impl` (GPT-5.6-luna, high) assigned READ-ONLY phase 3–5 preparation; no implementation permitted before lower review/API freeze. Inventories ownership/cache/mutation contracts and lower API blockers while parent integrates fixes.

## Independent Lower Review Findings

- Reviewer confirmed LOW-005 (dead evaluator/tests), LOW-006 (public UNC path), and LOW-007 (strict decoded absolute/relative target validation).
- LOW-008 (medium): unparsed suffix dot components were appended without normalization/share-boundary checks in snapshot production path. Accepted; draft fix underway, production-path regression required.
- LOW-009 (low/medium): name-list response with PathConsumed != 0 accepted despite MS-DFSC 3.3.5.2/3.3.5.3. Accepted; strict invariant and malformed DOMAIN/DC regression assigned.
- Reviewer found no further confirmed lifecycle or compound-replay blocker in immutable code with supplied lifecycle tests. Lower review not approved until fixes rechecked.

- LOW-010 (low, independent test-coverage finding): oversized share-enumeration test only asserted encoded request size, not the runtime method. Accepted; restore actual Session listShareNames flow with oversized endpoint and fake IPC/bind responses, then verify runtime guard.
- Independent bounded lower review complete, with no additional confirmed runtime blockers beyond LOW005–9. Awaiting immutable fix snapshot and test evidence for LOW005–10 recheck.
- Upper read-only preparation confirms current public API is sufficient after path fixes; implementation remains gated on lower approval. Parent reiterated final link-target PATH_NOT_COVERED must fail, not unconditionally fetch another referral.

## Lower Fix Verification

- Fixed-code snapshot: `/tmp/go-smb2-lower-fixed-okns_hl5/tree`, with tracked.patch alongside.
- Implementer reports LOW005–10 fixed and full `go test ./... -timeout=120s` passed (root 30.34s).
- Parent focused race command covering External, ResolveSymlink, CAP/flags, Compound, Pinned, and oversized ListShareNames: passed 1.518s with timeout 120s.
- Parent `go test ./internal/dfsc ./internal/smbpath`: passed; `git diff --check`: clean.
- Independent fix recheck running against this immutable snapshot; all findings remain pending closure until reviewer verifies fixes and related valid-path behavior.

## Lower Recheck Result

- Independent reviewer rechecked and resolved LOW005–10: active evaluator coverage, exact public UNCs, strict target validation, suffix normalization, name-list consumed count, and runtime oversized enumeration test.
- LOW-011 (medium, confirmed): valid remote absolute `\\?\UNC\server\share\...` target rejected as local; MS-SMB2 2.2.2.2.1 requires this form. Accepted; normalize it to ordinary UNC while rejecting local/device forms.
- Related valid-path regression accepted for LOW-011 fix: safe absolute target dot components and target/suffix separator joining need normalization without rewriting server/share. Relative root escape remains rejected per explicit agreed contract.
- Parent independently read MS-SMB2 2.2.2.2.1 PathBuffer and MS-FSCC 2.1.5.1 evidence. Lower boundary remains pending this focused fix/recheck.

- LOW-011 independently resolved. Parent focused race for ResolveSymlink/NormalizeSymlinkTarget/External passed 1.414s; diff check clean. Immutable changed files at `/tmp/go-smb2-low011-nj1oh0d4`.
- LOW-012 (low/medium, confirmed): absolute UNC root-level `..` must act as `.` per MS-FSCC 2.1.5.1; current normalizer rejects it. Accepted, absolute-only correction and repeated-root-dot cases assigned. Relative escaping links remain rejected per explicit plan. This is the only remaining independent lower finding.

- LOW012 fix frozen at `/tmp/go-smb2-low012-zk3b98l5` (share_io.go/share_io_test.go overlays). Absolute root parents are no-ops, relative escape policy unchanged, exact same/cross-share cases added.
- Parent `go test . -run 'TestResolveSymlink' -timeout=120s`: passed 0.290s; diff check clean. Implementer full suite passed. Narrow independent final lower recheck pending.

## Lower Boundary Approved / Upper Work Started

- Independent reviewer approved phases 1–2 after rechecking LOW005–12; no substantiated lower finding remains. Earlier LOW001–4 lifecycle/compound fixes also covered by review and passing tests. MIG001 removed; PRE002–3 satisfied. PRE001 mutation boundary remains an upper implementation requirement.
- Lower public API and internal/smbpath frozen. Upper owner cannot change lower/shared files without parent assignment.
- `upper_impl` (GPT-5.6-luna, high) owns dfs/ and replacement/migration of internal/dfsc/resolver.go/tests; implements phases3→4→5 in order with milestone handoffs.
- `upper_external_tests` (GPT-5.6-luna, high) owns new root dfs_external_test.go only; public fake multi-server coverage, reusing existing external wire helpers. No overlapping writes.
- Parent owns integration/docs and reviews actual code/test output. Final fresh independent review still required after upper completion.

## Live Integration Migration

- Parent migrated TestDFSIntegration to dfs.DFS and absolute UNCs; direct Session/Mount calls remain only for independent storage checks and share enumeration.
- Replaced obsolete multi-Mount/Unmount lifecycle scenario with Client.Close invalidating an already open target File and rejecting new operations.
- Recursive cleanup replaced with explicit file and empty-directory cleanup; upper API intentionally has no RemoveAll. Cross-share rename asserts dfs.ErrCrossShareRename.
- Live tests remain unexecuted because Docker and server configuration are unavailable; integrated compile remains pending upper implementation.
- Draft upper review observations sent to implementer: atomic cache/creation coalescing, preserving target hint identity on refresh, target-set membership equivalence, and nil/zero Client panic prevention. These require implementation/tests and independent review before closure.

- README integration coverage now describes DFS Client.Close invalidation and the shared DFS/symlink traversal limit. AGENTS.md's obsolete NewClient configuration-panic exception was replaced with the agreed Dial error requirement.
- Further draft upper checks sent to owner: successful reparse metadata requires final-object classification; Rename must share exploration state between both probes; active cycle detection must survive continuation; only Remove/Rename prohibit share-root administration. Formal review awaits the tested handoff.

## Upper Test Fixture Review

- Parent inspected independent public-test draft and requested corrections before accepting evidence: allow read-only preflight CREATEs while counting destructive request access/disposition and SET_INFO; provide valid symlink reparse contents rather than treating REPARSE_POINT alone as safe; test successful namespace reparse metadata separately; synchronize coalesced waiters on wire events; count transport Dials when asserting no target connection.
- These are test-quality corrections, not relaxed mutation guarantees. Upper production and external tests remain implementing.

- upper_lifecycle_tests (fresh GPT-5.6-luna, high) owns new dfs/client_test.go only, independently testing phase3 through simulated wire transport. Upper implementer excludes this file; owns all production and resolver tests.
- Parent flagged draft broken-session retention (share-only invalidation cannot reconnect) and changed-path DFS continuation after a lower same-share symlink; owner assigned fixes and regression coverage.

## Public Upper API Test Milestone

- Independent dfs_external_test.go covers File binding/display, DFS→cross-share symlink→DFS, initial same-share symlink updated referral path, cached/uncached link Remove protection, successful namespace reparse metadata rejection, ordinary child/final symlink Remove, cross-share Rename without destructive requests, target-free Symlink/Readlink, waiter cancellation, and Close during Dial.
- Agent normal selection count5, race count2, and all-package external selection passed. Parent independently ran `CGO_ENABLED=1 go test -race . -run '^TestExternalDFS' -count=1 -timeout=120s`: passed 1.428s, after inspecting final fixture corrections.
- Parent compiled README dfs example with `go test /tmp/go-smb2-dfs-readme-5daqcyt2/example.go -run '^$'`: passed. Migrated live integration tests compile as part of root tests but remain unexecuted.
- Additional external regression pair assigned: LINK target followed by same-share symlink and changed-path DFS must continue; unchanged final LINK-target PATH_NOT_COVERED must fail without another query. Existing tests exercise different traversal shapes.

- External test agent completed the additional changed-path LINK continuation, unchanged final LINK rejection, and alternating traversal termination cases; normal count5/race count2/all-package selected tests passed.
- Parent ported baseline TestResolverReferralBufferGrowth to public TestExternalGetDFSReferralsGrowsOutputBuffer (api_external_test.go), checking IOCTL request sizes, level4/path, successful retry and 56KiB cap. Focused race passed 1.405s; a final level4 assertion was added afterward and awaits final suite. One initial compile typo p.Data was corrected to existing PacketCodec.Body API before the passing run.

## Upper Ownership Test Milestone and Review Follow-up

- Independent dfs/client_test.go uses real Dialer/Session net.Pipe fixtures for case-insensitive coalescing, canceled waiters retained establishment, endpoint-specific factories, Close during creation, concurrent Close results, File invalidation, and stale-generation recovery. Agent normal package, client tests count20, package race passed. Parent inspected fixture source; independent targeted execution pending final blocked-send addition.
- Parent requested a true synchronous TREE_CONNECT Write block: original fixture waits after reading the request and therefore covers response blocking only. New test must allow five-second graceful deadline plus scheduling overhead.
- Parent found unjoined retired-session Close goroutines in draft invalidateSession/invalidateRoute; requested retaining/tracking generations so Client.Close waits for all owned shutdown work, plus rejecting late share publication from invalidated generation.

## Independent Upper Review Started

- Parent verified lifecycle focused race including actual blocked TREE_CONNECT Write: `CGO_ENABLED=1 go test -race ./dfs -run '^TestClient' -count=1 -timeout=120s`, passed 6.026s. Test owner independently confirms expected five-second shutdown deadline, waiters synchronized without sleeps.
- Immutable review snapshot `/tmp/go-smb2-upper-review-mf8m2iji/tree`, with tracked.patch alongside; includes live migration, lower API, upper draft, and current tests.
- upper_review (fresh GPT-5.6-luna, high) independently reviews snapshot upper ownership/resolution/mutation boundaries and lower interactions. Live upper owner may continue fixes; changed files must be rechecked. Runtime ROOT/interlink/cache/failover external tests continue in non-overlapping root test file.
- This is the upper boundary review. Workflow still requires final integrated verification and a separate fresh whole-implementation reviewer.

## Upper Handoff / Runtime V1 Finding

- Upper implementer handed off all agreed APIs and claims full normal/race suites passed; owner did not provide detailed output. Parent verification and independent review remain required.
- Frozen handoff dfs/ and shared-state overlay: `/tmp/go-smb2-upper-handoff-4tshbjwx`; supplied to reviewer over earlier full snapshot. Includes retained retired Session map and Close joins plus generation publication guard. New external tests copied alongside.
- Independent external ROOT→LINK, interlink chain/cycle, candidate fallback/hint reuse, and expired TTL tests pass; V1 wire test exposes UP-V1 (medium): transient V1 referral response discarded because execute re-enters cache-based route. Target never receives CREATE; traversal limit reached.
- Parent reproduced with `go test . -run '^TestExternalDFSReferralTTLExpiryAndV1NonCaching/V1' -count=1 -timeout=120s`: failed as reported, root 0.333s.
- Owner assigned current-operation routing of uncached V1 responses (also expired-cache refresh returning V1), preserving no persistent V1 caching and final-link safety. No weakening of failing assertion. Independent reviewer notified.

## V1 Fix Verification

- Implementer fixed transient V1 routing and stale-entry eviction when refresh changes to V1. Actual comparison against handoff shows only dfs/resolver.go changed; immutable overlay `/tmp/go-smb2-upper-v1-fix-3n75_hdy/dfs/resolver.go` sent to reviewer.
- Parent `CGO_ENABLED=1 go test -race . -run '^TestExternalDFSReferralTTLExpiryAndV1NonCaching$' -count=1 -timeout=120s`: passed 2.598s.
- Parent added an external transition case for expired V3→V1, then a third Open that must query again. Test owner completed before parent edits; no overlap. Updated external test copied into V1-fix overlay.

## Integrated Verification in Progress

- Parent expired V3→V1→third-query transition test passed 1.396s. Independent V1 fix recheck remains pending.
- All tracked/untracked Go source passes gofmt -l; git diff --check clean.
- Migration audit found no executable NewClient/ClientConfig/NewDialer/DialerConfig/old dfsc resolver uses and no forbidden upper Mount/Unmount/WithContext/recursive methods. TestDialerConfigurationErrors is a substring search false positive. DFS detection uses only tree_conn.go Capabilities & SHARE_CAP_DFS; flag references are regression fixtures.
- Required `CGO_ENABLED=1 go test -race ./... -timeout=120s` is running against current integrated code. Formal upper review is still pending; final fresh whole-implementation review follows.

## Upper Review Findings and Full Race Result

- Required parent full race `CGO_ENABLED=1 go test -race ./... -timeout=120s` passed all packages: root 100.627s, dfs 6.030s. This result precedes UP003 production fix; final-code checks must account for that change.
- Independent UP-V1 recheck resolved, including transient route and stale V3→V1 third-operation query under race.
- UP002 initially reported high wrong-directory Rename mutation from changed destination symlink. Parent challenged server-following premise; exact MS-FSA2.1.5.15.12 destination-open failure propagation, MS-FSA2.1.5.1 Phase6 mandatory STOPPED_ON_SYMLINK, and MS-SMB2 error propagation refute transparent redirection. Reviewer withdrew confirmed finding. Ordinary directory identity replacement is not established as the specific symlink/DFS redirection defect and is outside this task's link handling scope. No invasive pinning policy added.
- UP003 (medium/high, confirmed): interlink selected target namespace share mounted before referral lookup, unnecessarily failing when IPC$ query allowed but namespace TREE_CONNECT denied. Owner fixed with a shareless namespace route and negative mount regression. Immutable dfs overlay `/tmp/go-smb2-upper-interlink-fix-rzwnxfux/dfs` sent for independent recheck.
- Separate functional gap under test: Remove/Rename through an unchanged same-share intermediate symlink may lose lower-resolved path during preflight and safely fail instead of operating on ordinary child. External test owner assigned realistic wire regression before any contract changes.

- UP003 independently resolved against interlink overlay. Parent new interlink regression race passed 1.012s. Reviewer external normal/race and dfs package race passed; storage/root/link behavior retained. UP002 withdrawal reaffirmed.
- Remaining upper functional coverage question is unchanged same-share intermediate-symlink mutation, currently assigned to external tests. Final fresh full implementation review awaits its resolution.

## UP004: Preserve Actual Mutation Preflight Path

- Independent external tests confirm valid Remove/Rename through a same-share intermediate symlink fail with ErrPathChanged; lower Lstat followed the link, but upper preflight retained the alias for mutation. This is a functional defect, separate from withdrawn UP002.
- Parent added scoped internal/smbpath CapturePath/RecordPath and a requestBuilder.sendRecvOnce hook recording the actual attempted CREATE full UNC. Recording includes a final NotExist destination after intermediate symlinks; the result alone grants no mutation permission. Public API and File display metadata remain unchanged.
- Plan G records the internal contract extension. Upper owner assigned successful/explicitly missing probe result consumption, copied resolved routes, and preserved traversal/display/DFS-link classification. Lower/shared files remain parent-owned.
- Independent upper reviewer assigned focused new shared/lower-hook contract review and subsequent upper fix recheck. Full required race must be rerun on final code after this lower hook and upper fix.

## UP004 Fix and Recheck

- Parent reproduced both original failures: focused external intermediate-symlink selection failed 0.349s with ErrPathChanged on original aliases.
- Upper consumes scoped captured path for successful/allowed missing probes and preserves original display/traversal state; uses copied route with same-server/share validation. Parent focused race for same-share intermediate Remove/Rename passed 1.396s.
- Parent inspection requested final correction: Readlink validation must use captured actual path under pinned context, not re-evaluate original alias. Owner applied; targeted normal/race checks passed (lower/shared unchanged).
- Immutable final UP004 overlay `/tmp/go-smb2-upper-path-fix-3v3qi88a` includes operations.go, request.go, smbpath context.go, plan and external tests. Sent for independent boundary recheck. External test owner adding combined intermediate-alias/final ordinary-symlink coverage.

- Independent combined intermediate-alias/final ordinary-symlink Remove regression passes, verifies canonical Readlink and destructive CREATE despite alias returning different reparse content, and no target connection. Agent focused race twice passed 1.446s; full external DFS selection passed 2.507s. Updated external test copied into UP004 overlay for reviewer.

## Final Candidate

- Consolidated immutable final candidate `/tmp/go-smb2-final-review-i34y6obp/tree`, tracked.patch alongside; includes all production fixes and completed external tests. Parent removed unused newly-added relativeUNC wrapper after confirming no callers; no behavior changed.
- Required full race after UP004: `CGO_ENABLED=1 go test -race ./... -timeout=120s` passed all packages, root 107.621s and dfs 6.025s. Final compile-only check accounts for removal of the unused wrapper during that run.
- Upper boundary final recheck pending; fresh final whole-implementation reviewer follows. No known unresolved confirmed finding beyond pending UP004 independent closure.

## Upper Approved / Fresh Final Review

- Upper reviewer independently approved consolidated final snapshot after rechecking UP004 shared/lower capture and upper consumption. No substantiated upper finding remains. Reviewer full normal, dfs+smbpath race, external normal/race and targeted mutation/cycle/path tests passed.
- Final compile-only `go test ./... -run '^$' -timeout=120s` passed all packages (root 0.361s), including unused-helper removal.
- final_review (fresh GPT-5.6-luna, high) now independently reviews the whole consolidated immutable implementation, baseline, specifications, resolved findings, test fixtures and actual results. Does not edit. Parent edits only documentation/status during review.

## Fresh Final Review Findings

- FIN001 (medium, confirmed): refresh mutates published referral metadata still referenced by active routes; root/interlink reads can race and route kind can diverge from selected share/shareless state. Assigned upper_impl immutable routing metadata with concurrent regression.
- FIN002 (medium, confirmed): both symlink error/reparse decoders accept flags beyond absolute0/relative1. Assigned strict flag validation and malformed/valid decoder tests.
- FIN003 (low, confirmed): malformed UTF16 surrogate units in symlink substitute/print names are replaced during decoding rather than rejected. Assigned strict UTF16 validation preserving valid Unicode cases.
- FIN004 (low, accepted API contract discrepancy): GetDFSReferrals accepts bare domain names outside documented empty/slash-domain/full-UNC forms. Assigned minimal argument-form check and rejection/valid cases.
- final_lower_fixes (fresh GPT-5.6-luna, high) owns only internal/smb2 response/fscc decoder files/tests and referrals.go/tests. Parent/shared/upper files excluded.
- Additional PathConsumed0 root/link concern unconfirmed; reviewer asked for exact V1 versus later-version specification evidence before any decoder change.
- Full previous checks passed but these cases were missing. Final completion paused for fixes, independent recheck, and final-code verification. No publication.

- FIN001 owner fixed refresh to publish a cloned entry/target slice and added concurrent active-route regression. Frozen files `/tmp/go-smb2-fin001-fix-jo43csdg/dfs` sent for final reviewer recheck. Parent `CGO_ENABLED=1 go test -race ./dfs -run 'Refresh|Target|Interlink' -count=1 -timeout=120s`: passed 1.015s.
- Parent checked MS-DFSC3.2.5.5 header construction: root PathConsumed must cover first two components; link must cover matched complete prefix. MS-DFSC2.2.5.1 shows no V1 exception. Await reviewer confirmation before removing old zero-consumed storage acceptance; DOMAIN/DC name-list zero remains required.

- FIN001 independently resolved: reviewer confirms cloned published metadata and no new issue.
- FIN005 (confirmed strict-decoding defect): PathConsumed0 accepted for V1–V4 storage entries, could construct an incorrect public TargetPath. Reviewer and parent independently confirmed no version exception in MS-DFSC3.2.5.5/2.2.5.1; DOMAIN/DC name-list zero remains valid. Parent rejects zero for nonempty non-name-list responses, leaves empty response policy unchanged.
- FIN005 regression validates V1–V4 positive controls and rejects zero-consumed mutations. Two old valid-layout fixtures had zero headers corrected to actual matched-root lengths, preserving layout/string assertions. `CGO_ENABLED=1 go test -race ./internal/dfsc -count=1 -timeout=120s`: passed 1.011s after fixture correction.
- FIN002–4 owner completed code and focused normal/race pass; parent inspection requested a FIN004 test correction because two-leading single-component `server` is a valid DC form and nil Session errors alone cannot prove early argument rejection. No production defect in that correction.

## Final Fix Recheck Candidate

- FIN005 independently resolved: valid V1–4 storage, V3/V4 name-list zero, malformed storage zero, existing UTF16/component checks and empty responses verified.
- FIN004 tests corrected: arbitrary valid DC labels preserved; invalid-form public error must match path validation and must not be net.ErrClosed. Owner focused normal/race pass.
- Consolidated immutable final fixes `/tmp/go-smb2-final-fixes-pvtjm51z/tree`, tracked.patch alongside. Final reviewer assigned FIN002–4 focused recheck and final closure; FIN001/FIN005 already closed.
- Snapshot Go files pass gofmt; git diff --check clean. Parent required `CGO_ENABLED=1 go test -race ./... -timeout=120s` running against this frozen code. Parent edits only documentation/status.

## Completion

- Final required `CGO_ENABLED=1 go test -race ./... -timeout=120s` passed against frozen final code: root 99.946s, dfs 6.025s, internal/dfsc 1.011s, internal/smb2 1.066s, all other packages passed/cached.
- Fresh final reviewer independently closed FIN001–005 and found no additional substantiated defect in the consolidated final-fixes snapshot. UP-V1/UP003/UP004 and lower findings are resolved; UP002 withdrawn with specification evidence.
- Reviewed coverage includes ownership/shutdown, cancellation, CAP_DFS, compound replay, cache refresh, V1–4 decoding, symbolic links, UNC/suffix handling, mutation boundaries, manual APIs, and File display paths.
- Documentation, API migration audit, examples, formatting and diff checks are complete. All subagents used GPT-5.6-luna with high reasoning as requested.
- No real Samba/Windows test run was possible: Docker is absent and no external server configuration was provided. Migrated integration tests compile but remain unverified against real servers.
- No commits, pushes, PRs, or publication performed. Baseline and immutable review/fix snapshots retained at the paths recorded above.

## Post-workflow simplification

- User requested removal of the identified redundant designs. Removed stale
  sentinel API documentation; referral continuation uses DFSReferralError via
  errors.As and retains the underlying response through Unwrap.
- Mkdir, Truncate, Chmod, and Chtimes now execute their lower operation directly
  through the existing continuation handler. Removed the general mutation
  preflight wrapper, its follow-final branch, and unreachable route fallback.
  Remove/Rename retain their protected preflight and pinned mutation paths.
- Removed duplicate zero-value initialization and unused session/share metadata;
  session invalidation uses a single retirement path with generation checks.
- Added a public Chtimes regression whose server rejects read-attribute access;
  the timestamp update succeeds and executes once. Focused test passed.
- Final cleanup validation: `CGO_ENABLED=1 go test -race ./... -timeout=120s`
  passed (root 99.864s, dfs 6.025s; remaining packages passed/cached).
  `git diff --check` passed. No commit created.
