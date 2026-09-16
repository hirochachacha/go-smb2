# Implementation Plan for SMB / DFS Separation

Status: All phases are complete with local verification and independent review. Real-environment verification remains incomplete. Final results and limitations are recorded in [DFS_IMPLEMENTATION_STATUS.md](DFS_IMPLEMENTATION_STATUS.md). User agreements are recorded in [DFS_DESIGN.md](DFS_DESIGN.md).
This plan translates those agreements into implementation contracts, sequencing, and verification criteria.
Creating this file does not initiate implementation, commits, or publication.

For later execution by an agent, provide [DFS_EXECUTION_WORKFLOW.md](DFS_EXECUTION_WORKFLOW.md).
It defines the execution procedure from pre-implementation review through implementation,
independent review, and fixes.

## Approach and Priorities

1. Read AGENTS.md, DFS_DESIGN.md, and this plan.
2. Use the ms-specs skill to read relevant sections when working on Microsoft protocol requirements.
3. Implement the phases below in dependency order, with focused tests and independent review at each phase.
4. Finish with external-package API tests and multi-server integration verification.

Prioritize the user's agreements. If the plan conflicts with specifications or actual code,
report the evidence and proposed correction, then update the plan. Do not change functional
scope merely to accommodate a type design. Do not add DC discovery, DFS namespace
administration, compatibility paths, or automatic DFS configuration flags.

Preserve current uncommitted changes as existing work. At the start, inspect git status and
diff, and record the starting commit and working-tree changes. Do not reset them.

## A. Package Boundaries and Public API

### smb2

The following signatures define the implementation contract. Do not retain old API forms
that lack these arguments or return values for compatibility.

```go
func (d *Dialer) Dial(ctx context.Context, serverName string) (*Session, error)
func (s *Session) Close() error
func (s *Session) Mount(ctx context.Context, shareName string) (*Share, error)
func (s *Session) ListShareNames(ctx context.Context) ([]string, error)
func (s *Session) GetDFSReferrals(ctx context.Context, path string) (*DFSReferralResponse, error)
```

- Dialer exposes all current ClientConfig options directly as public fields and is constructed
  with a struct literal, such as &smb2.Dialer{Credentials: credentials, TransportDialer: transportDialer}.
  Do not provide DialerConfig or NewDialer.
- Validate configuration in Dial and return errors rather than panicking. Public API inputs
  must not cause panics, except for nil contexts.
- Concurrent Dial calls are supported. Callers must not modify the Dialer or referenced
  configuration, including slices, while it is in use (including by dfs.DFS).
  Apply defaults and normalization per call without mutating shared configuration.
- Dial returns an independent connection and Session even for the same serverName.
- Do not retain Dialer.Close, a ClientConfig alias, the old NewClient, or the old Client.Mount.
- ShareName contains only a share name. The server is fixed when Session is created.
- The public Session wraps the private wire session. Do not expose wire session / conn internals.

### Referral Responses

Use the existing validated decoder in internal/dfsc and copy results into public types.
Do not alias internal types or expose them in public signatures.

Use the following public types as the baseline. Document field semantics in Go doc as well.

```go
type DFSReferralResponse struct {
    PathConsumed uint16       // UTF-16 byte count in the request's DFS wire path
    HeaderFlags uint32
    Prefix string             // Matched UNC prefix
    Entries []DFSReferralEntry // Preserve response order
}

type DFSReferralEntry struct {
    Version uint16
    ServerType uint16
    Flags uint16
    TTL time.Duration
    DFSPath string
    DFSAlternatePath string
    NetworkAddress string     // Referral target as returned in the response
    TargetPath string         // UNC with the unparsed suffix appended exactly once
    SpecialName string
    ExpandedNames []string    // Preserve name-list responses too
}
```

- Define the necessary public constants for HeaderFlags, ServerType, and Flags using specification values.
- Preserve root/link, interlink, target set boundary, failback, and name-list information.
- The low-level retrieval API must return name-list responses correctly even without domain discovery.
- For name-list responses, leave Prefix and TargetPath empty and return SpecialName / ExpandedNames.
- Accept a full UNC for ROOT/LINK requests, an empty string for DOMAIN requests, and a path containing
  only the domain name (`\domain` / `\\domain`) for DC requests. Do not reuse Mount validation that
  requires a share name.
- Preserve the empty DOMAIN request string on the wire, followed by its terminator. Fix the existing
  ReferralRequest.normalizedPath behavior that converts an empty string to a backslash.
  Normalize nonempty requests to the DFS wire form with one leading backslash.
- Support for DOMAIN/DC input forms and name-list decoding does not include automatic DC discovery.
- Generate Prefix / TargetPath from validated PathConsumed. Do not use the byte count as a Go string
  index. Validate UTF-16 surrogate boundaries and path component boundaries.
- Do not conflate V1 cache eligibility or its lack of TTL with V2 and later versions.
- Storage referrals with entries require nonzero PathConsumed in every version;
  V3/V4 DOMAIN/DC name-list responses require zero. Empty responses carry no
  entry classification.
- Do not require the host/domain in GetDFSReferrals.path to match the Session endpoint.
  Preserve low-level use cases that query another server, such as a DC, about that namespace.

### Errors Carrying Continuation Information

```go
type SymlinkError struct {
    Path string               // Actual full UNC of the CREATE that stopped
    Target string             // Normalized SubstituteName; remains relative if relative
    Relative bool
    UnparsedPath string       // Suffix validated and extracted using response lengths
    ResolvedPath string       // Full UNC to access next, with the suffix already appended
    // Keep the underlying ResponseError in a private field
}
func (e *SymlinkError) Error() string
func (e *SymlinkError) Unwrap() error

type DFSReferralError struct {
    Path string               // Actual full UNC of the stopped CREATE, after symlink traversal
    // Keep the underlying ResponseError in a private field
}
func (e *DFSReferralError) Error() string
func (e *DFSReferralError) Unwrap() error
```

- Both errors must expose the underlying ResponseError and original NTSTATUS through Unwrap.
- Upper-layer continuation must use errors.As to retrieve DFSReferralError.Path.
- If following a symlink within the same Share results in PATH_NOT_COVERED, store the updated CREATE
  path in DFSReferralError.Path. Keep the original UNC in the outer PathError or equivalent wrapper.
  Issue referral requests and match referral prefixes against the updated Path.
- External callers must be able to continue with the same Session.GetDFSReferrals(ctx, e.Path)
  using this error, without private Share fields or internal context metadata.
- Do not unconditionally treat a failure of GetDFSReferrals itself or a final link target as an
  instruction to obtain another referral. The upper layer must also check the root/link resolution context.
- Create SymlinkError only when continuation to a validated UNC is possible.
  Use separate invalid-response or unsupported errors for malformed responses, local drives, and similar cases.
- Follow links within the current share in the lower layer. Return the error when crossing shares or servers.
- Validate relative link '..' components against the share boundary. Do not let '..' rewrite the UNC
  server/share components or silently clamp a reference outside the share to the share root.
  Return an error if a valid continuation UNC cannot be constructed.
- Identify NTSTATUS with errors.As / errors.Is, not string matching.
- Do not retry merely because an arbitrary subsequent compound operation has the same status.
  Allow continuation only on paths where CREATE stopped and subsequent mutations are confirmed unexecuted.

### dfs

```go
func New(dialer *smb2.Dialer) *Client
func (c *Client) Close() error
```

Path operations use the same argument types and ordering as the current Share, interpreting
path/name arguments as absolute UNCs. Limit the method set to the design document's list.
Provide the following public errors, wrapped in PathError / LinkError.

- ErrCrossShareRename: Rename whose resolved endpoints are on different shares.
- ErrDFSLinkOperation: Administration operations such as Remove / Rename on a DFS link itself.
- ErrShareRootOperation: Removal or rename of the share root itself.

Do not add a new generic FS interface, WithContext, Mount, or recursive operations.

## B. Passing the Original UNC and Exploration State

Preserve the contract of returning the same *smb2.File type. Do not mutate private state
through a public SetName, File copying, unsafe, linkname, or global registration callbacks.

Implementation approach: introduce internal/smbpath, depending only on the standard library,
to share per-operation internal metadata between smb2 and dfs through context.

- Store the original UNC, operation-wide traversal count, and visitation state.
- Use a dedicated private context key without changing the public context contract.
- Do not use this metadata as session or authentication configuration.
- dfs creates it at operation entry. For standalone smb2 use, create it at lower-level operation entry.
- Pass the same state through internal cross-share retries without resetting the count.
- When exploring multiple candidates, distinguish the active exploration path from the operation-wide
  traversal limit. Do not reject legitimate revisits with a simple permanent visited set.
  Account for the same name occurring at different processing stages.
- Rename must retain both original paths and use the correct display name for each side being resolved.

Internally, File stores separate actual-operation and display paths. Copy the original UNC
when creating File; do not retain the context or exploration state itself in File.
File.Name, PathError, and LinkError use the display path. Handle operations, copyFile,
and base information passed to Stat use the actual operation path.
Preserve the existing os.FileInfo.Name contract of returning only the file name.

This is an internal implementation choice. Independent review may replace it with an approach
that satisfies the same public contract if it introduces unnecessary state coupling.
However, the upper- and lower-layer owners must not independently implement competing approaches.

## C. Implementation Phases

### 1. Dialer / Session and a Single-Tree Foundation

Scope: client.go, session.go, tree_conn.go, share.go, share_enum.go, credentials.go,
transport_dialer.go, conn.go, transport.go, and their callers.

- Move ClientConfig fields directly onto Dialer and implement independent Dial calls through Dialer.
  Return configuration errors from Dial and keep concurrent calls free of configuration mutation.
- Refactor clientSession into the public Session and remove back-references such as client / entry.
- Remove Share ownership of the DFS resolver. Store the UNC root and SHARE_CAP_DFS on the tree.
- Construct CREATE wire paths and flags at a shared send boundary.
  Cover both createFile and requestBuilder paths. Do not append the prefix twice on retries.
- Make Session.Close idempotent. Concurrent Close callers must wait for the same shutdown completion.
- Combine an internal shutdown context with transport shutdown so that Close cannot wait forever on
  a blocked send. Bound graceful LOGOFF attempts with an internal constant and always close the
  transport during shutdown. Use an initial limit of five seconds; do not expose it as configuration.
- On deadline expiry, close the transport without acquiring the send mutex held by conn.send.
  Calling only the current conn.close from a timer is insufficient because it acquires that mutex.
  Transport shutdown must release synchronous send/receive, after which connection state and pending
  requests can be finalized under the mutex. Races between graceful completion and deadline expiry
  must not leave duplicate Close calls or unfinished work.
- Verify that Close on the built-in TCP/QUIC Transports releases blocked send/receive, and document
  this transport contract. Close must wait for its shutdown goroutines to finish.
- Define transport ownership on negotiate/authentication failure or cancellation during Dial.
  Context cancellation must be able to terminate Dial's own transport even during synchronous I/O.
- Do not route ordinary per-request cancellation through Session.Close.
- Do not introduce reference counting for the session registry.

Completion criteria: Two concurrent Dial calls use separate connections. Session remains usable
after the last Unmount. Shares/Files become unusable after Session.Close. A DFS share identified
only by its capability receives the correct CREATE request.

### 2. Referral Retrieval, Symlink Continuation, and File Display Names

Scope: new public referral types and errors, internal/dfsc/dfsc.go, share_io.go,
request.go, share.go, file.go, notify.go, and internal/smbpath.

- Implement public GetDFSReferrals and conversion to public referral types.
- Lazily create a dedicated IPC$ tree owned by Session and close it in Session.Close.
  Reuse that dedicated tree without racing with Unmount of ordinary Shares.
- Follow symlinks within the same share; return SymlinkError when crossing shares.
- Convert CREATE's PATH_NOT_COVERED into DFSReferralError containing the actual request path.
- For UNC targets, encode SubstituteName in the correct NT UNC form and keep PrintName separate.
- Readlink only returns the target. Do not check existence of or connect to Symlink's target.
- Separate File's display UNC from its actual path.

Completion criteria: An external smb2_test package can retrieve referrals and manually follow
cross-share links using errors.As. A same-share symlink followed by a DFS referral can also resume
from the updated Path. No access to private ResponseError.data is required.
Verify DOMAIN/DC requests on the wire.

### 3. dfs.DFS Connection Ownership and Shutdown

Scope: dfs/client.go, dfs/session.go, and other files organized by responsibility within the package.

- Retain Sessions per server and Shares per share within each Session.
- Coalesce concurrent creation for the same key. Do not hold the entire Client mutex during I/O.
- Tie the establishment context to the Client lifetime. Each waiter can stop waiting using its own
  context. Cancellation of the first waiter must not cancel shared connection establishment.
- Even if all waiters leave, let establishment finish under Client ownership and retain its result.
  Do not add machinery to count the last waiter and discard the connection.
- Close must follow this sequence:
  1. Under the mutex, enter the closing state and reject new acquisitions and registration of new results.
  2. Cancel the Client lifetime context and start closing all owned Sessions.
     Do not first wait for Dial/Mount/IPC$ creation to finish.
  3. Creation paths check the closing state before registration and close Sessions created too late.
     Mount on an existing Session can leave blocked synchronous I/O when that Session shuts down.
  4. Wait for all creation paths and Session.Close calls to finish, then publish Close completion.
- Do not hold the Client mutex while calling Session.Close or waiting. Dial owns its in-progress
  transport and stops it through the lower-level shutdown path when the Client lifetime context ends.
- Concurrent Close calls wait for the same completion notification and shutdown result.
  Document that termination of uncooperative user-provided factories cannot be guaranteed.
- Invalidate entries broken by communication errors only after confirming the entry generation.
  An old error must not remove a newly created connection.

Completion criteria: No connection leaks in Close races with Dial, authentication, or Mount.
Canceling one waiter does not affect other waiters or existing Sessions.
Existing Files become unusable after Client.Close.

### 4. Combined DFS and Symlink Path Resolution

Scope: the dfs resolver and path handling, including the destination of internal/dfsc/resolver.go.

- Keep wire decoding in internal/dfsc and move the connection-owning resolver into dfs.
  Do not retain the old resolver as a compatibility implementation.
- Separate direct handling of ordinary shares from referral handling for DFS shares.
- Use longest-prefix cache matching at component boundaries. Separate server/share from the remaining path.
- Handle TTL, V1 non-caching, target sets and ordering, selected candidates, and interlinks.
- For PATH_NOT_COVERED on a root target, request referrals using DFSReferralError.Path.
  If a same-share symlink changed the path, do not query again using the original UNC.
  Do not unconditionally fetch another referral for the same status on a final link target.
- Send SymlinkError.ResolvedPath back through UNC resolution. Do not append UnparsedPath again.
- Connect and query using the supplied name without guessing or special-casing domain-like names.
- Retain whether the final object is a DFS link itself in resolution state.
  Do not lose this classification when substituting a cached referral early.

Retry contract:

| Condition | Behavior |
| --- | --- |
| Network unavailable before connection establishment | May try the next referral candidate |
| Authentication/permission error, context completion, or invalid referral response | Return the error |
| CREATE stopped at DFS/symlink and mutations confirmed unexecuted | Resolve and retry |
| Connection lost after CREATE succeeds, or mutation outcome unknown | Do not automatically repeat the operation |
| Read/Write failure on an existing File | Do not replace File with another target |

Completion criteria: Verify DFS → symlink → DFS, same-share UNC, cross-share UNC, cycles,
TTL expiry, and multiple candidates using a small number of simulated servers.
Test path concatenation separately from original UNC display.

### 5. Path Operations and Destructive Operation Boundaries

Scope: dfs/file.go, dfs/directory.go, and similar files. Do not create a monolithic generic wrapper.

- Implement Open / OpenFile / Create / Stat / Lstat / ReadDir first.
- Then build operations such as ReadFile / WriteFile that can operate through File.
- Operations that do not return a File must close acquired Files on both success and failure.
- Lstat / Readlink / Remove do not follow the final symlink, but do follow intermediate symlinks.
- Resolve intermediate DFS links leading to a Readlink object or Symlink creation location.
  Do not resolve Symlink.target; preserve the meaning of relative targets.
- Remove follows intermediate symlinks and removes the object it reaches (os.Remove semantics).
  Reject a namespace-resolved DFS link itself or a share root, but do not re-validate the final
  reparse payload: a server-reported reparse point is removed as an ordinary object.
- Resolve both Rename endpoints' namespace/share and reject a cross-share Rename. The destination's
  intermediate symlinks are resolved by the server when it applies SET_INFO.
- Do not emulate cross-share Rename with copying.
- Preserve existing Share result types for Statfs and other operations.

Completion criteria: Verify on the server side that Remove/Rename of a DFS link itself sends
no delete/mutation request to its referral target. Explicitly specified ordinary objects beneath
it remain operable. Removing an ordinary symlink does not delete its target.

### 6. Caller Migration and Overall Verification

- Migrate README, examples, benchmarks, integration tests, and all old Client callers.
- Provide public-package usage examples for both the manual API and the dfs API.
- Document server naming and domain-resolution scope, Close lifetimes, the UNC requirement,
  and operations that are not exposed.
- Search for remaining old Client API calls, old resolver usage, and DFS detection based on share flags.
- Do not delete tests to pass a phase. Replace tests of superseded behavior with tests of the new contract.
- At completion, update the status in the design and this plan, distinguishing implemented from unverified work.

## D. Verification and Completion Criteria

### Required Checks

1. gofmt and git diff --check.
2. Focused tests for each phase. Observe wire boundaries using net.Pipe or equivalent;
   do not limit tests to checking internal field assignments.
3. External-package tests: manual SymlinkError traversal, GetDFSReferrals, and dfs.Open
   returning *smb2.File while preserving the original UNC.
4. Full suite: `CGO_ENABLED=1 go test -race ./... -timeout=120s`.
5. Inspect existing integration test procedures and run them in available Samba/Windows environments.
   Do not claim real-environment tests were run when unavailable. Record reasons and unverified items.

Regression coverage must include:

- Distinguishing CAP_DFS-only responses from ShareFlags-only responses.
- DFS paths without links, intermediate links, multiple candidates, and referrals to another namespace.
- PathConsumed / UnparsedPathLength for non-ASCII paths and exactly-once suffix appending.
- Same-share UNC, another share, another server, relative '..', and unsupported local drives.
- Alternating symlink and referral traversal cannot bypass limits.
- Closed Shares, operations after File.Close or Client.Close, and races with connection establishment.
- Invalid Dialer configuration returns an error without panicking; concurrent Dial calls do not
  mutate shared configuration or race while applying defaults.
- A same-share relative symlink followed by a DFS link uses the updated path for referral requests.
  Verify both external callers resuming through public errors and automatic dfs traversal.
- With a simulated transport blocked in send, Client.Close / Session.Close do not stall on the send
  mutex. Operations and Close finish after transport shutdown. Under the same conditions,
  canceling an individual operation alone must not close the transport.
- Wire inputs for empty DOMAIN, single-component DC, and ROOT/LINK requests; name-list responses
  must not incorrectly generate Prefix / TargetPath.
- Mutations whose response was lost after CREATE are not resent to another candidate.
- Distinguishing a DFS link itself from a directory beneath it.
- Keeping File.Name, File errors, and os.FileInfo.Name semantics distinct.

Passing an intermediate phase is not overall completion. Complete the public API scope,
resolve independent review findings, and finish required verification before declaring the work complete.

## E. Agent Implementation and Review Workflow

### Recommended Sequence

1. **Pre-implementation review**: Read the design, plan, and actual code without changing code.
   Check that the public API can support the upper layer and that ownership/retry contracts are consistent.
2. **Integration owner freezes contracts**: Incorporate pre-review findings into the plan.
3. **Implement phases 1–2**: Complete the lower-level API first and verify it from external-package tests.
4. **Implement phases 3–5**: Build the upper layer on the shared foundation contract.
   Delegate only work that can proceed independently.
5. **Phase 6 and independent final review**: Verify specifications and actual code, not just plan adherence.
6. **Fix and re-review**: Return findings to the responsible owner and recheck fixes and relevant tests.

Do not assign implementation and final approval to the same agent. Reviewing completed layer
boundaries reduces integration rework compared with a single review after all implementation.

### Responsibilities

- Integration owner: public types, internal/smbpath, coordination of shared-file edits, and integration tests.
- Lower-layer owner: phases 1–2; Session / Share / wire handling and externally usable continuation information.
- Upper-layer owner: phases 3–5; implement dfs after the lower-level API is frozen.
- Independent reviewer: return evidence-based findings without modifying implementation code.

Do not implement both layers in parallel before their API is settled. When sharing a working tree,
multiple owners must not edit the same file. When using separate checkouts, also transfer the
uncommitted design, plan, and existing changes so all owners share the same implementation baseline.

### Implementation Task Template

> Read AGENTS.md, DFS_DESIGN.md, and DFS_IMPLEMENTATION_PLAN.md.
> You own phase N and may edit scope X. The public contracts you depend on are fixed as Y.
> If assumptions conflict with actual code or specifications, report them rather than introducing
> workarounds or reducing scope. Implement and test your assignment against its completion criteria.
> Return changes, verification performed, unverified items, and handoff notes for other owners.
> Do not edit outside your assignment, commit, or publish.

### Review Task Template

> You are given AGENTS.md, the design, the plan, the implementation baseline and current diff,
> and test results. Independently verify design conformance and implementation correctness without
> changing code. Do not assume the plan itself is correct; read relevant Microsoft specifications,
> callees, and tests. For each finding, provide severity, file/line, concrete triggering conditions,
> contract violation or impact, evidence, and a proposed fix direction. Separate unverified concerns
> from confirmed defects. Focus on cancellation/Close, sending UNCs to the wrong tree, mistaken
> deletion targets, alternating symlink/DFS traversal, duplicate execution on retry, and practical
> API usability from another package.

Provide actual code diffs and test evidence, not just documents, to reviewers.
Plan adherence alone does not establish completion; look for behavioral counterexamples.

## F. Pre-Implementation Review Corrections

- Missing DFS continuation path: added DFSReferralError and tests for resuming after same-share symlinks.
- Close ordering and send mutex: added a lower-level shutdown path that does not block transport shutdown,
  explicit Client.Close ordering, and tests with blocked sends. Preserved per-operation cancellation isolation.
- Incomplete name-list request inputs: specified DOMAIN/DC forms, preservation of empty wire paths,
  and public response representation.
- Query tree ownership: aligned the design and plan on lazy creation and reuse of Session-dedicated IPC$,
  released when Session closes.

## G. Execution Contract Clarifications

- PRE-001: resolution retains whether the complete requested object is a DFS link,
  including cache hits and links targeting ordinary subdirectories. Remove and both
  Rename endpoints validate this before mutation. If intermediate paths change after
  validation, fail closed rather than silently following a new path during mutation.
- PRE-002: a typed continuation error is itself proof that CREATE stopped and all
  subsequent compound mutations were confirmed unexecuted. Do not expose a typed
  continuation when any later result is successful, missing, or otherwise uncertain.
  This avoids a second public retry-state API. Ordinary errors never authorize replay.
- PRE-003: validate PathConsumed at UTF-16 and complete-component boundaries before
  constructing public Prefix/TargetPath values.
- Uncached upper resolution uses typed CREATE continuation errors; no public IsDFS
  accessor is needed. Ordinary shares do not require referral queries.
- Traversal limits are per layer: the SMB layer bounds same-tree symbolic links per CREATE
  (clientMaxSymlinkDepth) and the DFS layer bounds referral resolution (maxReferralDepth).
- The DFS layer keeps display names on dfs.File. Open returns *dfs.File wrapping the lower
  *smb2.File; the lower layer no longer receives display names through context.
- Destructive Remove/Rename use os.Remove/os.Rename semantics: the final component is not
  followed, intermediate symlinks are followed, and a Rename destination is resolved by the
  server. No cross-layer pinned/probe state is carried.
