"""Atomic write, corrupt-storage rejection, and result-id traversal tests
for ResultStore -- spec sections 23-24, 75, 111, 117."""

from __future__ import annotations

import json

import pytest

from skillguard.errors import (
    CorruptResultError,
    PathSecurityError,
    PersistenceError,
    ValidationError,
)
from skillguard.persistence import ResultStore, load_json_strict


def _save(store: ResultStore, result_id: str = "run-1") -> None:
    store.save(
        result_id,
        audit={"audit_id": result_id, "status": "COMPLETE"},
        findings=[],
        capabilities={"declared": [], "observed": []},
        evidence=[],
        report_markdown="# report\n",
    )


class TestResultStoreBasics:
    def test_save_then_load_round_trips(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        _save(store)
        data = store.load("run-1")
        assert data["audit_id"] == "run-1"
        assert data["schema_version"] == 1

    def test_output_root_rejects_existing_file(self, tmp_path):
        f = tmp_path / "not_a_dir"
        f.write_text("x")
        with pytest.raises(PathSecurityError):
            ResultStore(f)

    def test_save_rejects_traversal_result_id(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        with pytest.raises((PathSecurityError, ValidationError)):
            store.save(
                "../escape",
                audit={"audit_id": "x", "status": "COMPLETE"},
                findings=[],
                capabilities={},
                evidence=[],
                report_markdown="",
            )
        # nothing should have leaked outside the output root
        assert not (tmp_path / "escape").exists()


class TestRootSwapAfterConstruction:
    def test_save_rejects_write_after_root_identity_changed(self, tmp_path):
        """Spec section 22/109: construct the store, then have the output
        directory's identity change (deleted and recreated) before a write.
        save() must refuse rather than writing into the new directory."""
        import shutil

        out_dir = tmp_path / "out"
        store = ResultStore(out_dir)
        assert store.root.verify_unchanged() is True

        shutil.rmtree(out_dir)
        out_dir.mkdir()  # new directory, same path, different identity

        with pytest.raises(PersistenceError):
            _save(store)


class TestLoadJsonStrictErrors:
    def test_read_failure_raises_persistence_error_not_os_error(self, tmp_path):
        directory_not_a_file = tmp_path / "a_directory"
        directory_not_a_file.mkdir()
        with pytest.raises(PersistenceError):
            load_json_strict(directory_not_a_file)


class TestCorruptStorage:
    def test_empty_json_object_is_corrupt(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        loc = store.location_for("run-1")
        loc.audit_json.parent.mkdir(parents=True)
        loc.audit_json.write_text("{}")
        with pytest.raises(CorruptResultError):
            store.load("run-1")

    def test_empty_list_is_corrupt(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        loc = store.location_for("run-1")
        loc.audit_json.parent.mkdir(parents=True)
        loc.audit_json.write_text("[]")
        with pytest.raises(CorruptResultError):
            store.load("run-1")

    def test_truncated_json_is_corrupt_not_json_decode_error(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        loc = store.location_for("run-1")
        loc.audit_json.parent.mkdir(parents=True)
        loc.audit_json.write_text('{"schema_version": 1, "audit_id"')
        with pytest.raises(CorruptResultError):
            store.load("run-1")

    def test_wrong_schema_version_is_corrupt(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        loc = store.location_for("run-1")
        loc.audit_json.parent.mkdir(parents=True)
        loc.audit_json.write_text(
            json.dumps(
                {
                    "schema_version": 999,
                    "audit_id": "x",
                    "status": "COMPLETE",
                    "findings": [],
                    "capabilities": {},
                }
            )
        )
        with pytest.raises(CorruptResultError):
            store.load("run-1")

    def test_missing_required_key_is_corrupt(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        loc = store.location_for("run-1")
        loc.audit_json.parent.mkdir(parents=True)
        loc.audit_json.write_text(json.dumps({"schema_version": 1, "audit_id": "x"}))
        with pytest.raises(CorruptResultError):
            store.load("run-1")

    def test_corrupt_data_never_becomes_empty_success(self, tmp_path):
        """The critical invariant: loading corrupt data must raise, never
        silently return an empty/'clean' result that looks like a
        successful audit with no findings."""
        store = ResultStore(tmp_path / "out")
        loc = store.location_for("run-1")
        loc.audit_json.parent.mkdir(parents=True)
        loc.audit_json.write_text("not json at all {{{")
        try:
            result = store.load("run-1")
        except CorruptResultError:
            pass
        else:
            pytest.fail(f"expected CorruptResultError, got a result: {result!r}")


class TestAtomicWrite:
    def test_no_partial_file_visible_on_crash_path(self, tmp_path, monkeypatch):
        """If writing fails partway through, no half-written file should
        replace the target path."""
        import skillguard.persistence as persistence_mod

        store = ResultStore(tmp_path / "out")
        loc = store.location_for("run-1")

        original_replace = persistence_mod.os.replace

        def boom(*args, **kwargs):
            raise OSError("simulated crash during replace")

        monkeypatch.setattr(persistence_mod.os, "replace", boom)
        with pytest.raises(OSError):
            persistence_mod.atomic_write_json(loc.audit_json, {"a": 1})
        assert not loc.audit_json.exists()
        # no leftover temp files
        if loc.audit_json.parent.exists():
            leftovers = [
                p for p in loc.audit_json.parent.iterdir() if p.name.startswith(".audit.json.")
            ]
            assert leftovers == []
        monkeypatch.setattr(persistence_mod.os, "replace", original_replace)
