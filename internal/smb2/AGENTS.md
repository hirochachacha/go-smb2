# Decoder Contract (`internal/smb2`)
All wire-format decoders in `internal/smb2` follow a two-phase contract:

- **Type:** Every decoder is a named `[]byte` slice type (e.g.,
  `type FooDecoder []byte`).
- **`IsInvalid() bool`:** Performs all validation required to make
  getters safe — minimum length, field offsets, buffer bounds, and
  semantic constraints mandated by the applicable Microsoft
  specification. Converting a raw `[]byte` into a decoder is the trust
  boundary: callers MUST call `IsInvalid()` and check for `true` before
  accessing any getter on a decoder obtained that way. `IsInvalid()` is
  the sole validation boundary.
- **Getters:** Simple field accessors only. After `IsInvalid()`
  returns `false`, every getter is guaranteed safe to call without
  further bounds checks. Do NOT add defensive length or offset
  guards inside getters — that would duplicate `IsInvalid()` and
  add noise without safety benefit. All new protocol-mandated
  validation belongs in `IsInvalid()`, not in individual getters.
- **Child decoders:** A getter that returns another decoder type
  (e.g. `CreateResponseDecoder.FileId()`,
  `NegotiateResponseDecoder.Contexts()`) exposes a region already
  covered by the parent's `IsInvalid()`. `IsInvalid()` must either call
  the child's `IsInvalid()` or its own length/bounds checks must subsume
  the child's. Callers MUST NOT re-validate such a child.
- **Raw byte getters:** A getter that returns raw `[]byte` (e.g.
  `Output()`, `Data()`, `SecurityBuffer()`, `ErrorData()`) does NOT
  return a validated decoder. Converting those bytes into a decoder is
  a new `[]byte` → decoder conversion and requires a fresh
  `IsInvalid()`.
- **Header / payload split:** Decoders whose variable-length payload may
  be received separately from the fixed header (READ, WRITE, IOCTL,
  QUERY_DIRECTORY, CHANGE_NOTIFY) split validation:
  - `IsInvalidHeader()` validates the fixed structure and the fields
    needed to locate the payload. It makes header getters safe, but NOT
    payload getters (`Data()`, `Output()`).
  - `IsInvalidPayload()` validates the payload region. It may read header
    fields without its own length guards, so it MUST only be called after
    `IsInvalidHeader()` has returned `false`.
  - `IsInvalid()` is `IsInvalidHeader() || IsInvalidPayload()` and is the
    normal entry point. Payload getters are safe only after it returns
    `false`.
  Header-only callers, such as direct-I/O reception where the payload
  lives outside the packet buffer, call `IsInvalidHeader()` and validate
  the payload separately.
- **Special case — absent fields:** When a field is permitted to be
  absent — because its length is 0, its offset is 0 for a length-less
  list, or the feature it belongs to is not present for the negotiated
  dialect — the getter returns `nil` / `""`. This is the meaning of the
  field, not a bounds guard: there is no buffer to return, so the getter
  does not compute `offset - header_size`. Apart from this factual
  absent-case return, getters MUST NOT contain any defensive length or
  offset guard.
