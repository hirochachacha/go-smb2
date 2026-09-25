# Corpus setup

Use this procedure when setting up or refreshing the specification corpus.
Ordinary specification lookups do not require index maintenance.

## Generate Markdown

With the specification DOCX files in `docx/` and Pandoc installed, run from the
repository root:

```bash
python3 .agents/skills/ms-specs/scripts/setup_specs.py --no-qmd
```

The converter replaces generated directories for the supplied specifications
and writes `specs/INDEX.md`. The `--no-qmd` option keeps conversion independent
of where QMD runs; omitting it also resets collections and updates a local index.
Without `--no-qmd`, the script registers the single
`ms-specs` collection, a corpus context, and a path context for each converted
specification. Each specification context includes its name, full title, and
known subject areas; unrecognized specifications still receive a title context.

## Index maintenance

Run index maintenance where the generated paths are accessible to qmd. The
CLI's working directory can select a project-local `.qmd` index; use the same
index for maintenance and retrieval.

Inspect existing collections with `qmd collection list`. If registering the
corpus separately from conversion, add its directory as `ms-specs` when absent:

```bash
qmd collection add .agents/skills/ms-specs/specs --name ms-specs
```

Use `qmd context add qmd://ms-specs/<SPEC> "<description>"` to attach each
specification's name, full title, and subject areas. The conversion script does
this automatically when run without `--no-qmd`.

After refreshing source files, run `qmd update`. Generate embeddings with
`qmd embed -c ms-specs` when semantic search is required.

Verify with a known identifier, then retrieve a returned document ID:

```bash
qmd search "SMB2_FLAGS_RELATED_OPERATIONS" -c ms-specs -n 5
qmd get '#<docid>'
```
