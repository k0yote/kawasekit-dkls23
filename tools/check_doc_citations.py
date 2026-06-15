#!/usr/bin/env python3
"""Guard against stale `file.rs:NNN` citations in the audit docs.

The audit documents under `docs/` are line-anchored: they cite specific source
lines (e.g. `signing.rs:581`). Those line numbers silently rot whenever
`dkls23-core` changes — any inserted line shifts every citation below it. This
tool snapshots the *content* of every cited source line into a lock file; CI
fails when a cited line's content drifts from the snapshot, forcing the citation
(or the snapshot) to be re-verified.

Usage:
    python3 tools/check_doc_citations.py            # --check (CI mode)
    python3 tools/check_doc_citations.py --update    # re-bless the lock file

After intentionally editing a doc citation or a cited source line, run --update
and review the lock diff alongside the change.

Scope (v1): citations that resolve to a single source file — either
file-qualified (`signing.rs:581`, `ot/extension.rs:365`) or bare (`:581`)
attributed to (a) a preceding file-stem word, (b) the most recent `*.rs` mention
on the same line, or (c) the enclosing `### …` section heading when it names
exactly one file. Bare citations that cannot be attributed unambiguously are
*skipped and counted* (never silently dropped). Non-`.rs` citations are ignored.
"""
from __future__ import annotations

import argparse
import glob as globmod
import os
import re
from collections import namedtuple

SRC_SUBDIR = os.path.join("dkls23-core", "src")
# Coverage is opt-in, and only LIVING docs (whose citations track current source)
# belong here. audit-context.md is the system model — linted. audit-findings.md and
# audit-deepdive-signing.md are point-in-time audit records with as-of-audit line
# numbers (pinned historical via their banners; see issue #27) — deliberately NOT
# linted. architecture.md / security.md carry no line citations. Do not add the
# historical docs here; drift-linting a historical record against current source is wrong.
DEFAULT_DOCS = "docs/audit-context.md"
DEFAULT_LOCK = "docs/audit-citations.lock"

EN_DASH = "–"
_SEP = r"0-9/,\-" + EN_DASH  # characters allowed inside a line-spec besides a leading digit

QUALIFIED = re.compile(r"([A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*\.rs):([0-9][" + _SEP + r"]*)")
BARE = re.compile(r"`:([0-9][" + _SEP + r"]*)`")
RS_MENTION = re.compile(r"[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*\.rs")
RS_IN_BACKTICKS = re.compile(r"`([A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*\.rs)`")
HEADING = re.compile(r"^#{1,6}\s")
PRECEDING_WORD = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")
INT = re.compile(r"\d+")

Citation = namedtuple("Citation", "doc_line file lines raw")


class ResolveError(Exception):
    """A cited file token does not resolve to exactly one source file."""


class DanglingCitation(Exception):
    """A citation points past the end of (or before) its source file."""


def list_sources(repo_root):
    """Return repo-relative POSIX paths of every `*.rs` under the source dir."""
    root = os.path.join(repo_root, SRC_SUBDIR)
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith(".rs"):
                rel = os.path.relpath(os.path.join(dirpath, name), repo_root)
                out.append(rel.replace(os.sep, "/"))
    return sorted(out)


def _stems(sources):
    return {os.path.basename(s)[:-3].lower() for s in sources}  # strip ".rs"


def resolve_source(token, sources):
    """Resolve a cited token ('signing', 'signing.rs', 'ot/extension.rs') to one source path."""
    token = token.strip()
    if not token.endswith(".rs"):
        token += ".rs"
    matches = [s for s in sources if s == token or s.endswith("/" + token)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ResolveError(f"no source file matches {token!r}")
    raise ResolveError(f"ambiguous file token {token!r}: {matches}")


def _attribute_bare(line, pos, recent_file, context_file, sources, stems):
    """Return the source path a bare `:NNN` citation belongs to, or None if ambiguous."""
    pre = line[:pos]
    m = PRECEDING_WORD.search(pre)
    if m and m.group(1).lower() in stems:
        try:
            return resolve_source(m.group(1), sources)
        except ResolveError:
            pass
    if recent_file is not None:
        return recent_file
    return context_file


def parse_citations(text, sources):
    """Parse `text`; return (list[Citation], skipped_bare_count)."""
    stems = _stems(sources)
    cites = []
    skipped = 0
    context_file = None
    for doc_line, line in enumerate(text.splitlines(), start=1):
        if HEADING.match(line):
            resolved = []
            for tok in dict.fromkeys(RS_IN_BACKTICKS.findall(line)):
                try:
                    resolved.append(resolve_source(tok, sources))
                except ResolveError:
                    pass
            distinct = list(dict.fromkeys(resolved))
            context_file = distinct[0] if len(distinct) == 1 else None

        events = []
        for m in QUALIFIED.finditer(line):
            events.append((m.start(), 0, "q", m))
        for m in RS_MENTION.finditer(line):
            events.append((m.start(), 1, "m", m))
        for m in BARE.finditer(line):
            events.append((m.start(), 2, "b", m))
        events.sort(key=lambda e: (e[0], e[1]))

        recent_file = None
        for _pos, _ord, kind, m in events:
            if kind == "q":
                try:
                    f = resolve_source(m.group(1), sources)
                except ResolveError:
                    continue
                recent_file = f
                cites.append(Citation(doc_line, f, [int(x) for x in INT.findall(m.group(2))], m.group(0)))
            elif kind == "m":
                try:
                    recent_file = resolve_source(m.group(0), sources)
                except ResolveError:
                    pass
            else:  # bare
                f = _attribute_bare(line, m.start(), recent_file, context_file, sources, stems)
                nums = [int(x) for x in INT.findall(m.group(1))]
                if f is None:
                    skipped += 1
                else:
                    cites.append(Citation(doc_line, f, nums, m.group(0)))
    return cites, skipped


def snapshot_line(repo_root, relpath, lineno):
    """Return the trimmed content of `relpath`:`lineno` (1-indexed)."""
    path = os.path.join(repo_root, relpath)
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if lineno < 1 or lineno > len(lines):
        raise DanglingCitation(f"{relpath}:{lineno} out of range (file has {len(lines)} lines)")
    return lines[lineno - 1].strip()


def build_expected(repo_root, doc_files):
    """Snapshot every cited line.

    Return (mapping{key:content}, citations, skipped, dangling). Dangling
    citations (line past EOF) are collected rather than raised, so a single
    broken citation never aborts the whole run.
    """
    sources = list_sources(repo_root)
    mapping = {}
    all_cites = []
    skipped = 0
    dangling = []
    for doc in doc_files:
        with open(doc, encoding="utf-8") as fh:
            text = fh.read()
        cites, sk = parse_citations(text, sources)
        skipped += sk
        for c in cites:
            all_cites.append(c)
            for ln in c.lines:
                try:
                    mapping[f"{c.file}:{ln}"] = snapshot_line(repo_root, c.file, ln)
                except DanglingCitation as exc:
                    dangling.append(f"{c.file}:{ln} (doc line {c.doc_line}, {c.raw}) — {exc}")
    return mapping, all_cites, skipped, dangling


def _key_sort(key):
    path, _, line = key.rpartition(":")
    return (path, int(line))


def write_lock(lock_path, mapping):
    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as fh:
        fh.write("# Auto-generated by tools/check_doc_citations.py --update — do not hand-edit.\n")
        fh.write("# Maps every <source>:<line> cited by docs/*.md to that line's trimmed content.\n")
        fh.write("# Re-run --update after intentionally changing a citation or a cited source line.\n")
        for key in sorted(mapping, key=_key_sort):
            fh.write(f"{key}\t{mapping[key]}\n")


def read_lock(lock_path):
    out = {}
    if not os.path.exists(lock_path):
        return out
    with open(lock_path, encoding="utf-8") as fh:
        for line in fh.read().splitlines():
            if not line or line.startswith("#"):
                continue
            key, _, content = line.partition("\t")
            out[key] = content
    return out


def check(repo_root, doc_files, lock_path):
    """Return (ok, problems). Problems are human-readable strings."""
    lock = read_lock(lock_path)
    sources = list_sources(repo_root)
    problems = []
    seen = set()
    for doc in doc_files:
        with open(doc, encoding="utf-8") as fh:
            text = fh.read()
        cites, _skipped = parse_citations(text, sources)
        for c in cites:
            for ln in c.lines:
                key = f"{c.file}:{ln}"
                seen.add(key)
                try:
                    content = snapshot_line(repo_root, c.file, ln)
                except DanglingCitation as exc:
                    problems.append(f"DANGLING  {key}  (doc line {c.doc_line}, {c.raw}) — {exc}")
                    continue
                if key not in lock:
                    problems.append(f"UNLOCKED  {key}  (doc line {c.doc_line}) — run --update; now={content!r}")
                elif lock[key] != content:
                    problems.append(f"DRIFT     {key}  (doc line {c.doc_line}) — lock={lock[key]!r} now={content!r}")
    for key in lock:
        if key not in seen:
            problems.append(f"STALE     {key}  — in lock but no doc cites it; run --update")
    return (len(problems) == 0), problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="verify citations against the lock file (default action)")
    ap.add_argument("--update", action="store_true", help="regenerate the lock file instead of checking")
    ap.add_argument("--repo-root", default=os.getcwd())
    ap.add_argument("--docs", default=DEFAULT_DOCS, help="glob for docs (default: docs/*.md)")
    ap.add_argument("--lock", default=DEFAULT_LOCK)
    args = ap.parse_args(argv)

    doc_files = sorted(globmod.glob(os.path.join(args.repo_root, args.docs)))
    lock_path = os.path.join(args.repo_root, args.lock)
    if not doc_files:
        print(f"no docs matched {args.docs!r}")
        return 1

    if args.update:
        mapping, cites, skipped, dangling = build_expected(args.repo_root, doc_files)
        write_lock(lock_path, mapping)
        print(f"blessed {len(mapping)} cited lines from {len(cites)} citations "
              f"across {len(doc_files)} doc(s); {skipped} bare citation(s) unattributed/skipped")
        if dangling:
            print(f"\n{len(dangling)} DANGLING citation(s) point past EOF and were NOT blessed:")
            for d in dangling:
                print(f"  {d}")
            print("Fix these citations, then re-run --update.")
            return 1
        return 0

    ok, problems = check(args.repo_root, doc_files, lock_path)
    _mapping, cites, skipped, _dangling = build_expected(args.repo_root, doc_files)
    if ok:
        print(f"OK: {len(cites)} citations verified against {os.path.relpath(lock_path, args.repo_root)} "
              f"({skipped} bare unattributed/skipped)")
        return 0
    print(f"FAIL: {len(problems)} citation problem(s):\n")
    for p in problems:
        print(f"  {p}")
    print("\nIf the source genuinely moved, fix the citation in the doc; if the doc text was "
          "intentionally re-grounded, run:\n  python3 tools/check_doc_citations.py --update")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
