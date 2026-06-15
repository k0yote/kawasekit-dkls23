"""Tests for check_doc_citations.py (TDD — written before the implementation).

Run: python3 -m unittest tools/test_check_doc_citations.py
  or: python3 tools/test_check_doc_citations.py
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_doc_citations as cdc  # noqa: E402

EN_DASH = "–"


def write_lines(path: Path, n: int) -> None:
    """Create a source file whose line i has content 'l{i}' (1-indexed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"l{i}" for i in range(1, n + 1)) + "\n", encoding="utf-8")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.dir if False else self.tmp.name)
        src = self.root / "dkls23-core" / "src"
        write_lines(src / "protocols" / "signing.rs", 1200)
        write_lines(src / "protocols.rs", 600)
        write_lines(src / "utilities" / "multiplication.rs", 1000)
        write_lines(src / "utilities" / "proofs.rs", 1000)
        write_lines(src / "utilities" / "ot" / "extension.rs", 1000)
        write_lines(src / "utilities" / "ot" / "base.rs", 500)
        self.sources = cdc.list_sources(str(self.root))

    def tearDown(self):
        self.tmp.cleanup()


class TestResolve(Base):
    def test_resolve_basename(self):
        self.assertTrue(cdc.resolve_source("signing.rs", self.sources).endswith("protocols/signing.rs"))

    def test_resolve_subdir_qualified(self):
        self.assertTrue(cdc.resolve_source("ot/extension.rs", self.sources).endswith("utilities/ot/extension.rs"))

    def test_resolve_stem_without_ext(self):
        self.assertTrue(cdc.resolve_source("extension", self.sources).endswith("ot/extension.rs"))

    def test_resolve_missing_raises(self):
        with self.assertRaises(cdc.ResolveError):
            cdc.resolve_source("nonexistent.rs", self.sources)


class TestParse(Base):
    def parse(self, text):
        return cdc.parse_citations(text, self.sources)

    def test_qualified_single(self):
        cites, skipped = self.parse("see `signing.rs:687` here")
        self.assertEqual(skipped, 0)
        self.assertEqual(len(cites), 1)
        self.assertTrue(cites[0].file.endswith("protocols/signing.rs"))
        self.assertEqual(cites[0].lines, [687])

    def test_qualified_range_endash(self):
        cites, _ = self.parse(f"`signing.rs:777{EN_DASH}838`")
        self.assertEqual(cites[0].lines, [777, 838])

    def test_qualified_list_and_compound(self):
        cites, _ = self.parse(f"`signing.rs:580{EN_DASH}596/788{EN_DASH}804`")
        self.assertEqual(cites[0].lines, [580, 596, 788, 804])

    def test_bare_uses_heading_context(self):
        text = (
            f"### 3.7 Signing {EN_DASH} `protocols/signing.rs` (1200)\n"
            "Nonce sampled (`:329`).\n"
        )
        cites, skipped = self.parse(text)
        self.assertEqual(skipped, 0)
        self.assertEqual(len(cites), 1)
        self.assertTrue(cites[0].file.endswith("protocols/signing.rs"))
        self.assertEqual(cites[0].lines, [329])

    def test_bare_preceding_word_overrides_context(self):
        # Under a zero_shares-ish heading, "signing `:409`" must bind to signing.rs.
        text = (
            "### 3.5 Zero Shares\n"
            f"zero_sid composition (signing `:409{EN_DASH}415`).\n"
        )
        cites, skipped = self.parse(text)
        self.assertEqual(len(cites), 1)
        self.assertTrue(cites[0].file.endswith("protocols/signing.rs"))
        self.assertEqual(cites[0].lines, [409, 415])

    def test_bare_same_line_recent_rs(self):
        # "proofs.rs:388 ... `:667`" — the trailing bare cite inherits proofs.rs.
        cites, skipped = self.parse("M1 (`proofs.rs:388`), `:667` (CP)")
        self.assertEqual(skipped, 0)
        files = sorted(c.file for c in cites)
        self.assertEqual(len(cites), 2)
        self.assertTrue(all(f.endswith("utilities/proofs.rs") for f in files))
        self.assertEqual(sorted(l for c in cites for l in c.lines), [388, 667])

    def test_ambiguous_heading_skips_bare(self):
        text = (
            "### 3.11 Sessions — `signing.rs` (1), `proofs.rs` (2)\n"
            "state (`:5`).\n"
        )
        cites, skipped = self.parse(text)
        self.assertEqual(cites, [])
        self.assertEqual(skipped, 1)


class TestSnapshotAndCheck(Base):
    def doc(self, text):
        d = self.root / "docs"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "audit-context.md"
        p.write_text(text, encoding="utf-8")
        return [str(p)]

    def test_snapshot_line_trimmed(self):
        rel = "dkls23-core/src/protocols/signing.rs"
        self.assertEqual(cdc.snapshot_line(str(self.root), rel, 3), "l3")

    def test_dangling_line_raises(self):
        rel = "dkls23-core/src/protocols/signing.rs"
        with self.assertRaises(cdc.DanglingCitation):
            cdc.snapshot_line(str(self.root), rel, 99999)

    def test_update_then_check_passes(self):
        docs = self.doc("`signing.rs:3` and `multiplication.rs:5`")
        lock = str(self.root / "docs" / "citations.lock")
        cdc.write_lock(lock, cdc.build_expected(str(self.root), docs)[0])
        ok, problems = cdc.check(str(self.root), docs, lock)
        self.assertTrue(ok, problems)
        self.assertEqual(problems, [])

    def test_drift_is_detected(self):
        docs = self.doc("`signing.rs:3`")
        lock = str(self.root / "docs" / "citations.lock")
        cdc.write_lock(lock, cdc.build_expected(str(self.root), docs)[0])
        # mutate the cited source line -> drift
        sp = self.root / "dkls23-core" / "src" / "protocols" / "signing.rs"
        lines = sp.read_text(encoding="utf-8").splitlines()
        lines[2] = "TOTALLY DIFFERENT"
        sp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, problems = cdc.check(str(self.root), docs, lock)
        self.assertFalse(ok)
        self.assertTrue(any("signing.rs:3" in p for p in problems), problems)

    def test_missing_lock_entry_is_detected(self):
        docs = self.doc("`signing.rs:3`")
        lock = str(self.root / "docs" / "citations.lock")
        cdc.write_lock(lock, {})  # empty lock -> the citation is unaccounted
        ok, problems = cdc.check(str(self.root), docs, lock)
        self.assertFalse(ok)

    def test_build_expected_collects_dangling_without_crashing(self):
        docs = self.doc("valid `signing.rs:3` and broken `signing.rs:99999`")
        mapping, cites, skipped, dangling = cdc.build_expected(str(self.root), docs)
        self.assertIn("dkls23-core/src/protocols/signing.rs:3", mapping)
        self.assertNotIn("dkls23-core/src/protocols/signing.rs:99999", mapping)
        self.assertTrue(any("99999" in d for d in dangling), dangling)


if __name__ == "__main__":
    unittest.main(verbosity=2)
