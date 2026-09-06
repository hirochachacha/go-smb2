#!/usr/bin/env python3
"""
setup_specs.py: Extract and index Microsoft Open Specifications for ms-specs skill.

Converts .docx specifications in docx/ into section-numbered Markdown files in specs/
and synchronizes the QMD search collections ('ms-specs' and individual spec collections).

Usage:
  python3 .agents/skills/ms-specs/scripts/setup_specs.py [path/to/docx_or_directory] [options]

Examples:
  # Convert all docx files in skill docx/ to specs/ and sync with QMD
  python3 .agents/skills/ms-specs/scripts/setup_specs.py --clean

Options:
  -i, --input PATH      Input .docx file or directory containing .docx files (default: skill docx/)
  -o, --output PATH     Root output directory for specifications (default: skill specs/)
  --no-clean            Do not clean destination directory before generation (default: clean)
  --no-qmd              Skip automatic QMD collection registration and update
  -q, --quiet           Suppress verbose progress output
  -h, --help            Show this help message
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


def slug(text):
    s = text.lower()
    s = re.sub(r"^(appendix\s+[a-z]:?\s*)+", "", s)
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:40]


def get_spec_metadata(docx_path):
    """Extract short title (e.g. MS-SMB2) and full document title from docx."""
    base = os.path.basename(docx_path)
    m = re.search(r"\[?([A-Z0-9]+-[A-Z0-9]+)\]?", base)
    short_title = m.group(1) if m else re.sub(r"-\d+$", "", os.path.splitext(base)[0]).strip("[]")

    full_title = short_title
    try:
        with zipfile.ZipFile(docx_path) as z:
            with z.open("word/document.xml") as f:
                root = ET.parse(f).getroot()
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        w_p = "{%s}p" % ns["w"]
        w_t = "{%s}t" % ns["w"]
        p_texts = []
        for p in root.iter(w_p):
            t = "".join(x.text for x in p.iter(w_t) if x.text).strip()
            if t:
                p_texts.append(t)
                if len(p_texts) >= 5:
                    break
        if len(p_texts) >= 2 and "[" in p_texts[0] and ":" in p_texts[0]:
            full_title = p_texts[1]
    except Exception:
        pass

    return short_title, full_title


def extract_toc(docx_path):
    """Extract ordered TOC entries from word/document.xml."""
    with zipfile.ZipFile(docx_path) as z:
        with z.open("word/document.xml") as f:
            root = ET.parse(f).getroot()

    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    w_p = "{%s}p" % ns["w"]
    w_pStyle = ".//{%s}pStyle" % ns["w"]
    w_val = "{%s}val" % ns["w"]
    w_hl = ".//{%s}hyperlink" % ns["w"]
    w_anchor = "{%s}anchor" % ns["w"]
    w_r = "{%s}r" % ns["w"]
    w_t = "{%s}t" % ns["w"]

    tocs = []
    for p in root.iter(w_p):
        pStyle = p.find(w_pStyle)
        if pStyle is not None:
            val = pStyle.attrib.get(w_val, "")
            if val.startswith("TOC") and val != "TOCHeading":
                level = int(val[3:]) if val[3:].isdigit() else 1
                hl = p.find(w_hl)
                anchor = hl.attrib.get(w_anchor, "") if hl is not None else ""

                texts = []
                if hl is not None:
                    for r in hl.iter(w_r):
                        t = "".join(x.text for x in r.iter(w_t) if x.text).strip()
                        if t:
                            texts.append(t)

                if len(texts) >= 3 and texts[0].replace(".", "").isdigit():
                    sec_num = texts[0]
                    title = " ".join(texts[1:-1])
                    page = texts[-1]
                elif len(texts) == 2 and texts[0].replace(".", "").isdigit():
                    sec_num = texts[0]
                    title = texts[1]
                    page = ""
                elif len(texts) >= 2:
                    sec_num = ""
                    title = " ".join(texts[:-1])
                    page = texts[-1]
                else:
                    sec_num = ""
                    title = " ".join(texts)
                    page = ""

                tocs.append({
                    "level": level,
                    "sec_num": sec_num,
                    "title": title,
                    "page": page,
                    "anchor": anchor,
                })
    return tocs


def clean_markdown_text(text):
    """Strip Word indexref spans and unnecessary artifacts."""
    while '<span class="indexref"' in text:
        new_text = re.sub(
            r'<span class="indexref"[^>]*>(?:(?!<span class="indexref").)*?</span>',
            "",
            text,
            flags=re.DOTALL,
        )
        if new_text == text:
            new_text = re.sub(r'<span class="indexref"[^>]*>', "", new_text)
            new_text = re.sub(r"</span>", "", new_text)
            text = new_text
            break
        text = new_text
    return text


def compute_chapter_paths(tocs, spec_name):
    """
    Assign exactly 1 directory level (chapter) under the specification:
    docs/specs/<SPEC>/<CHAPTER>/<sec>-<title>.md
    """
    section_targets = []

    ch_lookup = {}
    for item in tocs:
        if item["level"] == 1 and item["sec_num"]:
            ch_lookup[item["sec_num"]] = f"{item['sec_num']}-{slug(item['title'])}"

    for item in tocs:
        sec = item["sec_num"]
        title = item["title"]
        parts = sec.split(".") if sec else []

        if not parts or not parts[0].isdigit():
            folder = slug(title)
            section_targets.append(f"{folder}/{folder}.md")
            continue

        ch = parts[0]
        ch_folder = ch_lookup.get(ch, f"ch-{ch}")

        # Depth cap for modular files:
        # Chapters 2 and 3 contain the vast majority of packet syntax and protocol rules.
        # Splitting up to Level 5 (e.g. 3.2.4.1.4, 3.3.5.2.7) ensures focused ~30-150 line files,
        # dramatically improving BM25/vector search precision and preventing token bloat on retrieval.
        cap = 5 if ch in ("2", "3") else 4
        chosen_parts = parts[:cap]
        sub = ".".join(chosen_parts)
        sub_item = next((x for x in tocs if x["sec_num"] == sub), item)
        fname = f"{sub}-{slug(sub_item['title'])}.md"

        section_targets.append(f"{ch_folder}/{fname}")

    return section_targets


def convert_single_spec(docx_path, out_specs_dir, clean=True, verbose=True):
    short_title, full_title = get_spec_metadata(docx_path)
    spec_dest_dir = os.path.join(out_specs_dir, short_title)

    if clean and os.path.exists(spec_dest_dir):
        if verbose:
            print(f"Cleaning existing directory: {spec_dest_dir}")
        shutil.rmtree(spec_dest_dir)

    os.makedirs(spec_dest_dir, exist_ok=True)

    if verbose:
        print(f"\n[{short_title}] Processing {docx_path}")
        print(f"  Title: {full_title}")
        print("  1. Extracting TOC...")
    tocs = extract_toc(docx_path)
    if verbose:
        print(f"     Found {len(tocs)} TOC entries.")

    with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tmp:
        raw_md_path = tmp.name

    try:
        if verbose:
            print("  2. Converting to Markdown using Pandoc...")
        cmd = ["pandoc", docx_path, "-t", "gfm", "-o", raw_md_path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Pandoc conversion failed: {res.stderr}")

        if verbose:
            print("  3. Cleaning markup and restoring section numbers...")
        with open(raw_md_path, "r", encoding="utf-8") as f:
            raw_text = f.read()

        clean_text = clean_markdown_text(raw_text)
        clean_lines = clean_text.splitlines(keepends=True)

        clean_header_indices = []
        for i, line in enumerate(clean_lines):
            if re.match(r"^#{1,6}\s+.*$", line):
                clean_header_indices.append(i)

        targets = compute_chapter_paths(tocs, short_title)
        section_entries = []
        for idx, item in enumerate(tocs):
            rel = targets[idx]
            section_entries.append({
                "index": idx,
                "level": item["level"],
                "sec": item["sec_num"],
                "title": item["title"],
                "rel_path": rel,
                "heading_line": clean_header_indices[idx] if idx < len(clean_header_indices) else None,
            })

        for entry in section_entries:
            line_idx = entry["heading_line"]
            if line_idx is not None:
                prefix = "#" * entry["level"]
                sec = entry["sec"]
                title = entry["title"]
                num_part = f"{sec} " if sec else ""
                clean_lines[line_idx] = f"{prefix} {num_part}{title}\n"

        # Consolidated full markdown
        consolidated_path = os.path.join(spec_dest_dir, f"{short_title}.md")
        if verbose:
            print(f"  4. Writing consolidated spec to {consolidated_path}...")
        with open(consolidated_path, "w", encoding="utf-8") as f:
            f.writelines(clean_lines)

        # Split into modular files under chapter folders
        if verbose:
            print("  5. Writing chapter-scoped section files...")
        files_dict = {}
        for i, entry in enumerate(section_entries):
            rel = entry["rel_path"]
            start_line = entry["heading_line"]
            next_start = None
            for j in range(i + 1, len(section_entries)):
                if section_entries[j]["rel_path"] != rel:
                    next_start = section_entries[j]["heading_line"]
                    break
            files_dict.setdefault(rel, {
                "start_line": start_line,
                "end_line": next_start,
                "sections": [],
            })
            files_dict[rel]["sections"].append(entry)

        for rel_path, info in files_dict.items():
            out_file = os.path.join(spec_dest_dir, rel_path)
            os.makedirs(os.path.dirname(out_file), exist_ok=True)
            start = info["start_line"]
            end = info["end_line"] if info["end_line"] is not None else len(clean_lines)
            lines_slice = clean_lines[start:end]

            header = f"[< Back to {short_title} Index](../INDEX.md)\n\n---\n\n"
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(header)
                f.writelines(lines_slice)

        # Spec-level INDEX.md
        index_path = os.path.join(spec_dest_dir, "INDEX.md")
        if verbose:
            print(f"  6. Writing Table of Contents to {index_path}...")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(f"# [{short_title}]: {full_title}\n\n")
            f.write(f"[< Back to All Specifications](../INDEX.md)\n\n")
            f.write(
                f"> Converted from `{os.path.basename(docx_path)}` and split into {len(files_dict)} modular files.\n\n"
            )
            f.write(f"Full single-file version: [{short_title}.md](./{short_title}.md)\n\n")
            f.write("## Table of Contents\n\n")

            for entry in section_entries:
                indent = "  " * (entry["level"] - 1)
                sec = entry["sec"]
                title = entry["title"]
                rel_file = entry["rel_path"]
                anchor = slug(f"{sec} {title}" if sec else title)
                link = f"./{rel_file}#{anchor}"
                disp = f"{sec} {title}" if sec else title
                f.write(f"{indent}- [{disp}]({link})\n")

        if verbose:
            print(f"  ✓ {short_title} completed: {len(files_dict)} modular files generated.")

        return {
            "short_title": short_title,
            "full_title": full_title,
            "dest_dir": spec_dest_dir,
            "files_count": len(files_dict),
            "toc_count": len(tocs),
        }

    finally:
        if os.path.exists(raw_md_path):
            os.remove(raw_md_path)


def generate_master_index(out_specs_dir, processed_specs):
    """Generate docs/specs/INDEX.md linking to all processed specifications."""
    master_index_path = os.path.join(out_specs_dir, "INDEX.md")
    with open(master_index_path, "w", encoding="utf-8") as f:
        f.write("# Microsoft Specifications Index\n\n")
        f.write(
            "This directory contains converted, section-numbered, and searchable Microsoft Open Specifications "
            "used in `go-smb2`.\n\n"
        )
        f.write("## Available Specifications\n\n")
        for spec in sorted(processed_specs, key=lambda x: x["short_title"]):
            st = spec["short_title"]
            ft = spec["full_title"]
            cnt = spec["files_count"]
            f.write(f"- **[{st}](./{st}/INDEX.md)**: {ft} *({cnt} modular files)*\n")
            f.write(f"  - [Table of Contents](./{st}/INDEX.md)\n")
            f.write(f"  - [Consolidated Single File](./{st}/{st}.md)\n\n")


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_DOCX_DIR = os.path.join(SKILL_DIR, "docx")
DEFAULT_SPECS_DIR = os.path.join(SKILL_DIR, "specs")


def sync_qmd(output_dir, processed_specs, verbose=True):
    """Automatically register and update QMD collections for converted specifications."""
    qmd_bin = shutil.which("qmd")
    if not qmd_bin:
        if shutil.which("bunx"):
            cmd_prefix = ["bunx", "@tobilu/qmd"]
        else:
            if verbose:
                print("\n[qmd] 'qmd' binary not found in PATH. Skipping QMD collection registration.")
            return
    else:
        cmd_prefix = [qmd_bin]

    if not os.path.isdir(".qmd"):
        if verbose:
            print("\n[qmd] .qmd index not found. Running `qmd init`...")
        subprocess.run(cmd_prefix + ["init"], check=False)

    res = subprocess.run(cmd_prefix + ["collection", "list"], capture_output=True, text=True)
    existing = set(re.findall(r"^([A-Za-z0-9_-]+)\s+\(qmd://", res.stdout, re.MULTILINE))

    # Path to register (relative to cwd if possible)
    rel_output_dir = os.path.relpath(output_dir, ".")
    root_name = "ms-specs"

    # 1. Reset collection: remove existing 'ms-specs' collection and legacy sub-collections
    #    to ensure a clean state without stale or deleted documents.
    if root_name in existing:
        if verbose:
            print(f"[qmd] Removing existing collection '{root_name}' to reset index...")
        subprocess.run(cmd_prefix + ["collection", "remove", root_name], check=False)

    for s in processed_specs:
        short_title = s["short_title"]
        if short_title in existing:
            if verbose:
                print(f"[qmd] Removing redundant sub-collection '{short_title}'...")
            subprocess.run(cmd_prefix + ["collection", "remove", short_title], check=False)

    # 2. Add overarching 'ms-specs' collection pointing to output_dir
    if os.path.isdir(output_dir):
        if verbose:
            print(f"[qmd] Adding collection '{root_name}' ({rel_output_dir})...")
        subprocess.run(cmd_prefix + ["collection", "add", rel_output_dir, "--name", root_name], check=False)

    # 3. Clean up orphaned embeddings/chunks and vacuum
    if verbose:
        print("[qmd] Cleaning up index...")
    subprocess.run(cmd_prefix + ["cleanup"], check=False)

    # 4. Update the index so all files are reflected
    if verbose:
        print("[qmd] Updating QMD index...")
    subprocess.run(cmd_prefix + ["update"], check=False)


def main():
    parser = argparse.ArgumentParser(
        description="Extract and index Microsoft Open Specifications (.docx) for ms-specs skill."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=DEFAULT_DOCX_DIR,
        help=f"Path to .docx file or directory containing .docx files (default: {os.path.relpath(DEFAULT_DOCX_DIR, '.')})",
    )
    parser.add_argument(
        "-i", "--input", dest="input_target", help="Alternative input path for .docx or directory"
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_SPECS_DIR,
        help=f"Root output directory for specifications (default: {os.path.relpath(DEFAULT_SPECS_DIR, '.')})",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Do not clean destination directory before generating files (default: clean)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress informational output",
    )
    parser.add_argument(
        "--no-qmd",
        action="store_true",
        help="Skip automatic QMD collection registration and update",
    )

    args = parser.parse_args()
    input_path = args.input_target or args.target
    verbose = not args.quiet
    clean = not args.no_clean

    if os.path.isdir(input_path):
        docx_files = sorted(glob.glob(os.path.join(input_path, "*.docx")))
        if not docx_files:
            print(f"No .docx files found in {input_path}", file=sys.stderr)
            sys.exit(1)
    elif os.path.isfile(input_path):
        docx_files = [input_path]
    else:
        print(f"Error: {input_path} is neither a file nor a directory", file=sys.stderr)
        sys.exit(1)

    processed_specs = []
    for docx_file in docx_files:
        res = convert_single_spec(docx_file, args.output, clean=clean, verbose=verbose)
        processed_specs.append(res)

    generate_master_index(args.output, processed_specs)
    if verbose:
        print(f"\n==========================================")
        print(f"All specifications converted successfully!")
        print(f"Master Index: {os.path.join(args.output, 'INDEX.md')}")
        for s in processed_specs:
            print(f"  - {s['short_title']}: {s['files_count']} modular files ({s['toc_count']} TOC items)")
        print(f"==========================================")

    if not args.no_qmd:
        sync_qmd(args.output, processed_specs, verbose=verbose)


if __name__ == "__main__":
    main()
