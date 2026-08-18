"""SG-R1-NEW-001 (partially fixed in Round 1) re-verification after the
SG2-001 rewrite of the walk/read engine: repeated legitimate use of the
production StaticScanner/DynamicWorkspace/ResultStore paths must never
produce a false ROOT_CHANGED / identity-mismatch / UNREADABLE_FILE from
normal activity alone. 100 iterations (per the audit's requirement),
against the real, currently-in-use _SecureWalker-based walk_tree_and_read
path -- not the older open_walk_entry-only test in
test_remediation_round1.py, which exercises a narrower surface."""

from __future__ import annotations

from skillguard.dynamic.workspace import DynamicWorkspace
from skillguard.paths import BoundRoot
from skillguard.persistence import ResultStore
from skillguard.static.scanner import StaticScanner

ITERATIONS = 100


class TestRepeatedStaticScanStability:
    def test_100_repeated_static_scans_no_false_root_changed(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")
        (target / "b.py").write_text("y = 2\n")

        for i in range(ITERATIONS):
            result = StaticScanner().scan(target)
            assert "ROOT_CHANGED" not in result.incompleteness_reasons, f"iteration {i}"
            assert "UNREADABLE_FILE" not in result.incompleteness_reasons, f"iteration {i}"
            assert result.files_scanned == 2, f"iteration {i}"


class TestRepeatedDynamicWorkspaceStability:
    def test_100_repeated_workspace_copies_of_same_source_no_false_positive(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")

        root = BoundRoot.bind(source)
        for i in range(ITERATIONS):
            with DynamicWorkspace(root) as ws:
                assert "ROOT_CHANGED" not in ws.incompleteness_reasons, f"iteration {i}"
                assert (ws.path / "a.py").exists(), f"iteration {i}"
                ws.verify_source_unchanged()  # must not raise


class TestRepeatedResultStoreSaveStability:
    def test_100_repeated_saves_to_same_output_root_no_false_positive(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        for i in range(ITERATIONS):
            assert store.root.verify_unchanged() is True, f"iteration {i}"
            loc = store.location_for(f"run-{i}")
            loc.audit_json.parent.mkdir(parents=True, exist_ok=True)
            (loc.audit_json.parent / "marker.txt").write_text(str(i))
        assert store.root.verify_unchanged() is True
