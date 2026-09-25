---
name: ms-specs
description: >-
  Look up Microsoft Open Specifications used in go-smb2: MS-DFSC, MS-DTYP,
  MS-FSA, MS-FSCC, MS-LSAD, MS-LSAT, MS-NLMP, MS-RPCE, MS-SMB2, MS-SPNG,
  and MS-SRVS. Use for specification questions, implementation, debugging,
  and compliance checks involving SMB2/SMB3, DFS, filesystem semantics and
  control codes, Windows data types and security, NTLM/SPNEGO authentication,
  RPC, LSA policy and name translation, or Server Service operations.
---

# Microsoft Open Specifications

Find and read the specification sections that govern the behavior under review.
The corpus is available as the QMD collection `ms-specs` and, when generated
locally, as section-numbered Markdown under `specs/` beside this skill.

## Source of truth

The Markdown specifications in this corpus are the single source of truth for protocol
formats, requirements, and semantics in this project. Answer specification
questions from these Markdown documents. Do not browse the
web to confirm, supplement, or replace their contents, check newer revisions,
or obtain citation links.

Web search is only for information outside the specifications, such as a
vendor implementation's observed behavior, product releases, or tooling.
Explain the external question being investigated and distinguish those findings
from normative specification requirements. A missing section or unclear
conversion is a corpus gap, not an out-of-specification question.

## Search and retrieve with qmd

Before using qmd, run `qmd skill show` and read its instructions for CLI
usage, search, and retrieval. Keep qmd usage guidance in that skill rather
than duplicating it here.

Use the `qmd` CLI to search and retrieve from the `ms-specs` collection.
The corpus index is `qmd://ms-specs/INDEX.md`; each specification also has
an `INDEX.md` for section numbers and cross-references. Section paths follow
`<SPEC>/<chapter>/<section>-<slug>.md`; deeper subsections can share a file.

Choose the source by responsibility: MS-SMB2 for SMB messages and processing,
MS-FSCC for file information classes and control codes, MS-FSA for filesystem
algorithms, MS-DTYP for shared data types, and MS-SRVS for server service RPC.
Follow references into other specifications as needed.

## Local fallback

The presence of local Markdown or a known section number is not a reason to
skip qmd. Read local specification files only when the CLI is unavailable,
a command fails, or the needed document is absent from its index. State the
specific reason before falling back; attempt the relevant command first.
Do not install tools or rebuild the index merely to perform a lookup.

When fallback is necessary, use the local corpus index at `specs/INDEX.md`
beside this skill, or search from the repository root:

```bash
rg -n 'SMB2_FLAGS_RELATED_OPERATIONS' .agents/skills/ms-specs/specs/MS-SMB2
```

## Read and substantiate

Retrieve the relevant section text before drawing conclusions; search snippets
are only leads. Prefer section files over consolidated specifications, and read
the surrounding conditions and referenced sections needed to interpret a rule.
Check both message structure and the applicable sending/receiving rules, paying
attention to client/server roles, dialects, and MUST/SHOULD/MAY distinctions.

Cite the specification name and section number, together with a retrieved path
or document ID and relevant lines. Distinguish normative requirements from
implementation choices and inferences. Report any unresolved gaps or ambiguity
in the Markdown source.

## Corpus maintenance

Missing search results do not by themselves justify rebuilding the corpus.
If neither QMD nor local files provide the needed source, report the gap.
For requested setup or refresh,
read [corpus setup](references/setup.md).
