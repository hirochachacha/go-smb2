# Coding & Design Guidelines

## Protocol Safety & Error Handling
- Strictly adhere to Microsoft specifications (such as MS-SMB2, MS-FSCC, MS-SRVS, ...). Refer to the `ms-specs` skill (`.agents/skills/ms-specs/SKILL.md`) for specification lookup and search instructions.
- Always validate slice bounds, fragment lengths, and payload boundaries when parsing wire protocol packets to prevent integer overflow and panics.
- Keep external dependencies minimal; prefer the Go standard library.

## Security Policy: Input Validation
- Distinguish validation of API arguments used for encoding from validation of encoded input being decoded. Decoding requires stricter validation, regardless of who supplies the encoded input.
- Keep validation of caller-provided API arguments used for encoding minimal, focused on preventing simple, common usage mistakes. Do not require exhaustive protocol validation of these arguments: generating a nonconforming request that the server rejects is not, by itself, a security finding and is outside the scope of security audits.
- Public APIs must not panic for any input, except when passed a nil `context.Context` or when calling a `MustXXX` API. `MustXXX` APIs are intended for inputs the caller knows are valid and may panic on invalid input. Invalid `Dialer` configuration must return an error from `Dial`. Validation needed to uphold this guarantee is allowed and remains within the scope of security audits.
- Treat all input being decoded as untrusted, including server responses and caller-provided encoded input. Validate it strictly against the applicable Microsoft specifications, including structural constraints and semantic correctness; detect and reject malformed or semantically invalid input. Missing or incorrect decoding validation is within the scope of security audits.

## Connection & Request Lifecycle
- A resource is closed only by the layer that owns it. A higher layer must not
  close a lower layer's resource directly; it requests teardown through the
  owner's lifecycle operation instead. For example, session code closes a
  connection via `conn.close`, never by closing the transport itself.
- A request's context cancellation or timeout must never close shared
  resources. Canceling a request must only send `SMB2 CANCEL` and affect that
  specific request; concurrent requests and sessions sharing the connection
  must not be disrupted. When a request cannot proceed, return the error and
  let the owning layer decide whether the connection is still usable.
- For zero-copy / direct reads where the transport writes directly into the
  caller's buffer, wait for in-flight transport reception to complete on
  cancellation so the caller buffer is safe from late writes without aborting
  the shared connection.

## File API Semantics
- File API behavior must conform to the semantics of the standard library `os` package, except for context handling and the concurrent-append limitation below.
- Atomic append across independently opened file handles, sessions, or clients
  is not guaranteed. Callers must coordinate multiple writers. Do not add
  implicit SMB locks solely to provide this guarantee. Single-writer append
  and copy operations remain in scope. As with `os.File`, the behavior of
  `Seek` on a file opened with `O_APPEND` is unspecified.
- Do not use `os.Is*` (e.g., `os.IsNotExist`, `os.IsPermission`); use `errors.Is` instead.
- Use `internal/path` for path operations instead of manipulating path
  separators directly. Joining, splitting, separator checks, normalization,
  and SMB/POSIX conversion belong in `internal/path`; callers should not
  implement them with separator literals or string operations.
- Keep separator conversion explicit: use `ToSMBPath` or `ToPOSIXPath` at
  format boundaries. `Normalize` and `NormalizePattern` operate on SMB
  paths and patterns without converting separators.

## Public API Boundaries
- Outside `x/protocol`, do not newly expose `protocol` types in public APIs.
  Existing exposure, including type aliases and `Share.Request`, is intentional
  and exempt; do not remove or replace it to satisfy this rule. Protocol errors
  may still appear nested in `Err` fields (e.g. `os.PathError.Err`). For new APIs,
  define independent interfaces where needed, even when their method sets
  duplicate protocol interfaces.

## Testing Guidelines
- Use TDD for behavior changes and bug fixes: write a failing test before
  changing production code, make it pass with the smallest change, then
  refactor. Skip new tests for reversible, low-impact changes that would
  only mirror the implementation.
- Default to running unit tests using `go test -short ./...`. In principle, unit tests are sufficient for general development and verification.
- Integration tests require a configured SMB server environment and should only be run on demand when specifically needed (e.g., via `go test ./...` without `-short`).

## Decoder Contract (`x/wire`)
- When implementing or using `x/wire` decoders, follow the contract in [x/wire/AGENTS.md](x/wire/AGENTS.md).
