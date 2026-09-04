---
name: ms-specs
description: >-
  Lookup and search Microsoft Open Specifications used in go-smb2 (including [MS-SMB2]
  and [MS-FSCC]). Use whenever implementing or debugging SMB2/SMB3 wire formats, packet
  structures, file information classes, FSCTL codes, negotiate contexts, signing, credits,
  encryption, session setup, or verifying compliance with Microsoft specifications.
---

# Microsoft Open Specifications (`docs/specs/`)

Specifications are located under `docs/specs/` as section-numbered Markdown files, indexed by `qmd`.

## Retrieval Methods

### 1. Direct File Access (Fastest & Exact)
Check [`docs/specs/MS-SMB2/INDEX.md`](file:///Users/hiro/d/go-smb2/docs/specs/MS-SMB2/INDEX.md) or [`docs/specs/MS-FSCC/INDEX.md`](file:///Users/hiro/d/go-smb2/docs/specs/MS-FSCC/INDEX.md) for section numbers.
Files follow the path pattern `docs/specs/<SPEC>/<chapter>/<section>-<slug>.md`:
- `docs/specs/MS-SMB2/2-messages/2.2.3-smb2-negotiate-request.md`
- `docs/specs/MS-SMB2/3-protocol-details/3.2.5.1-receiving-any-message.md`
- `docs/specs/MS-FSCC/2-structures/2.4.7-filebasicinformation.md`

### 2. Keyword Search (BM25)
For constants, struct names, error codes, and flags:
```bash
bunx @tobilu/qmd search "FileBasicInformation" -c ms-specs
```

### 3. Semantic Vector Search (Fast Vector Similarity)
For conceptual questions, behavior descriptions, or when exact keyword names are unknown:
```bash
bunx @tobilu/qmd vsearch "preauth integrity hash negotiation" -c ms-specs
```

### 4. Reading Results
Retrieve surrounding context or full section using document ID from search results:
```bash
bunx @tobilu/qmd get "<#docid>"
```
