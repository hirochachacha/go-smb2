---
name: ms-specs
description: >-
  Lookup and search Microsoft Open Specifications used in go-smb2 (including [MS-SMB2], [MS-FSCC], [MS-DTYP] and [MS-SRVS]). Use whenever implementing or debugging SMB2/SMB3 wire formats, packet
  structures, file information classes, FSCTL codes, negotiate contexts, signing, credits,
  encryption, session setup, or verifying compliance with Microsoft specifications.
---

# Microsoft Open Specifications (`.agents/skills/ms-specs/specs/`)

Specifications are located under `.agents/skills/ms-specs/specs/` as section-numbered Markdown files, indexed by `qmd`.

## Setup (One-time or when specs are missing)

On a fresh clone or if the specifications/index have not been built yet, run:
```bash
qmd init
python3 .agents/skills/ms-specs/scripts/setup_specs.py
```
This extracts Markdown files from `.agents/skills/ms-specs/docx/` into `.agents/skills/ms-specs/specs/` and automatically registers the `ms-specs` QMD collection.

## Retrieval Methods

### 1. Direct File Access (Fastest & Exact)
Check [`INDEX.md`](file:///Users/hiro/d/go-smb2/.agents/skills/ms-specs/specs/INDEX.md) for section numbers.
Files follow the path pattern `.agents/skills/ms-specs/specs/<SPEC>/<chapter>/<section>-<slug>.md`:
- `.agents/skills/ms-specs/specs/MS-SMB2/2-messages/2.2.3-smb2-negotiate-request.md`
- `.agents/skills/ms-specs/specs/MS-SMB2/3-protocol-details/3.2.5.1-receiving-any-message.md`
- `.agents/skills/ms-specs/specs/MS-FSCC/2-structures/2.4.7-filebasicinformation.md`

### 2. Keyword Search (BM25)
For constants, struct names, error codes, and flags:
```bash
qmd search "FileBasicInformation" -c ms-specs
```

### 3. Semantic Vector Search (Fast Vector Similarity)
For conceptual questions, behavior descriptions, or when exact keyword names are unknown:
```bash
qmd vsearch "preauth integrity hash negotiation" -c ms-specs
```

### 4. Reading Results
Retrieve surrounding context or full section using document ID from search results:
```bash
qmd get "<#docid>"
```
