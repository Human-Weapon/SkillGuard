"""Static scanner behavior: AST rule detection, malformed/binary/huge file
handling, and the "never imports the target" invariant."""

from __future__ import annotations

from skillguard.models import AnalysisStatus
from skillguard.static.python_ast import PythonAstScanner
from skillguard.static.scanner import StaticScanConfig, StaticScanner


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


class TestPythonAstRules:
    def test_detects_shell_true(self):
        src = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-001" in _rule_ids(result.findings)

    def test_distinguishes_shell_false_from_shell_true(self):
        src = "import subprocess\nsubprocess.run(['ls'])\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        ids = _rule_ids(result.findings)
        assert "SG-PY-009" in ids
        assert "SG-PY-001" not in ids

    def test_detects_os_system(self):
        src = "import os\nos.system('echo hi')\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-002" in _rule_ids(result.findings)

    def test_detects_eval(self):
        src = "eval('1+1')\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-004" in _rule_ids(result.findings)

    def test_detects_exec(self):
        src = "exec('x = 1')\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-005" in _rule_ids(result.findings)

    def test_detects_pickle_loads(self):
        src = "import pickle\npickle.loads(b'data')\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-008" in _rule_ids(result.findings)

    def test_detects_base64_into_exec(self):
        src = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        ids = _rule_ids(result.findings)
        assert "SG-PY-016" in ids
        assert "SG-PY-005" not in ids  # the more specific rule wins, not both

    def test_detects_network_import(self):
        src = "import socket\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-010" in _rule_ids(result.findings)

    def test_detects_environ_access(self):
        src = "import os\nx = os.environ['KEY']\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-011" in _rule_ids(result.findings)

    def test_detects_open_write_mode(self):
        src = "open('f.txt', 'w')\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-012" in _rule_ids(result.findings)

    def test_does_not_flag_open_read_mode(self):
        src = "open('f.txt', 'r')\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-012" not in _rule_ids(result.findings)

    def test_detects_ctypes(self):
        src = "import ctypes\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-013" in _rule_ids(result.findings)

    def test_survives_import_alias(self):
        src = "import subprocess as sp\nsp.run('x', shell=True)\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        assert "SG-PY-001" in _rule_ids(result.findings)

    def test_malformed_python_records_parse_error_not_crash(self):
        src = "def f(:\n    pass\n"
        result = PythonAstScanner().scan_source(relative_path="broken.py", source=src)
        assert result.parse_ok is False
        assert any(f.rule_id == "SG-PY-017" for f in result.findings)

    def test_capabilities_derived_from_findings(self):
        src = "import subprocess\nsubprocess.run('x', shell=True)\n"
        result = PythonAstScanner().scan_source(relative_path="a.py", source=src)
        from skillguard.capabilities import Capability

        assert Capability.PROCESS_SPAWN in result.capabilities


class TestStaticScannerIntegration:
    def test_scan_directory_is_complete_when_no_limits_hit(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        result = StaticScanner().scan(tmp_path)
        assert result.status == AnalysisStatus.COMPLETE
        assert result.files_scanned == 1

    def test_binary_file_does_not_crash_scan(self, tmp_path):
        (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\xff\xfe" * 100)
        (tmp_path / "ok.py").write_text("x = 1\n")
        result = StaticScanner().scan(tmp_path)
        assert result.status == AnalysisStatus.COMPLETE
        assert result.files_scanned == 2

    def test_huge_file_is_skipped_with_incompleteness_reason(self, tmp_path):
        big = tmp_path / "big.py"
        big.write_text("x = 1\n" * 100)
        config = StaticScanConfig(max_file_bytes=10)  # smaller than the file
        result = StaticScanner(config).scan(tmp_path)
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "FILE_TOO_LARGE" in result.incompleteness_reasons
        assert result.files_scanned == 0

    def test_file_count_limit_truncates_not_silently_succeeds(self, tmp_path):
        for i in range(10):
            (tmp_path / f"f{i}.py").write_text("x = 1\n")
        config = StaticScanConfig(max_files=3)
        result = StaticScanner(config).scan(tmp_path)
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "FILE_LIMIT_REACHED" in result.incompleteness_reasons
        assert result.files_scanned == 3

    def test_empty_file_does_not_crash(self, tmp_path):
        (tmp_path / "empty.py").write_text("")
        result = StaticScanner().scan(tmp_path)
        assert result.status == AnalysisStatus.COMPLETE

    def test_malformed_python_marks_incompleteness_and_continues(self, tmp_path):
        (tmp_path / "broken.py").write_text("def f(:\n    pass\n")
        (tmp_path / "ok.py").write_text("x = 1\n")
        result = StaticScanner().scan(tmp_path)
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "PYTHON_PARSE_ERROR" in result.incompleteness_reasons
        assert result.files_scanned == 2  # both files were still processed

    def test_findings_are_deterministically_ordered(self, tmp_path):
        (tmp_path / "z.py").write_text("eval('1')\n")
        (tmp_path / "a.py").write_text("exec('1')\n")
        r1 = StaticScanner().scan(tmp_path)
        r2 = StaticScanner().scan(tmp_path)
        assert [f.rule_id for f in r1.findings] == [f.rule_id for f in r2.findings]
        assert [f.file_path for f in r1.findings] == [f.file_path for f in r2.findings]


class TestNoTargetImport:
    def test_static_scan_never_imports_target_package(self, tmp_path):
        """A fixture whose import would create a marker file. Static scan
        must leave the marker absent -- spec sections 85/120."""
        marker = tmp_path / "IMPORTED_MARKER"
        pkg = tmp_path / "evil_pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text(
            f"from pathlib import Path\nPath(r'{marker}').write_text('imported')\n"
        )
        result = StaticScanner().scan(tmp_path)
        assert not marker.exists()
        assert result.status == AnalysisStatus.COMPLETE

    def test_static_scan_never_triggers_build_backend(self, tmp_path):
        """Parsing pyproject.toml is fine; a build backend must never run.
        There's no build tooling invoked here at all -- this asserts the
        scan completes using only text parsing, with no side-effect marker
        appearing (spec section 86/36)."""
        marker = tmp_path / "BUILD_RAN_MARKER"
        (tmp_path / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "evil_backend.api"\n'
        )
        # A malicious build backend module that would only run if imported.
        (tmp_path / "evil_backend.py").write_text(
            f"from pathlib import Path\nPath(r'{marker}').write_text('built')\n"
        )
        result = StaticScanner().scan(tmp_path)
        assert not marker.exists()
        assert any(f.rule_id == "SG-MANIFEST-004" for f in result.findings)


class TestSecretRedaction:
    def test_private_key_detected_and_not_leaked(self, tmp_path):
        secret_line = "-----BEGIN RSA PRIVATE KEY-----"
        (tmp_path / "key.pem").write_text(
            secret_line + "\nMIIabc...\n-----END RSA PRIVATE KEY-----\n"
        )
        result = StaticScanner().scan(tmp_path)
        matches = [f for f in result.findings if f.rule_id == "SG-SECRET-001"]
        assert len(matches) == 1
        assert secret_line not in matches[0].description

    def test_credential_assignment_detected_and_redacted(self, tmp_path):
        secret_value = "sup3r-s3cr3t-value-123"
        (tmp_path / "config.py").write_text(f'password = "{secret_value}"\n')
        result = StaticScanner().scan(tmp_path)
        matches = [f for f in result.findings if f.rule_id == "SG-SECRET-003"]
        assert len(matches) == 1
        assert secret_value not in matches[0].description
        assert secret_value not in matches[0].title

    def test_known_token_prefix_detected(self, tmp_path):
        (tmp_path / "leak.txt").write_text("aws_key = AKIAABCDEFGHIJKLMNOP\n")
        result = StaticScanner().scan(tmp_path)
        assert any(f.rule_id == "SG-SECRET-002" for f in result.findings)


class TestManifestScanning:
    def test_git_dependency_detected(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("mypkg @ git+https://example.com/mypkg.git\n")
        result = StaticScanner().scan(tmp_path)
        assert any(f.rule_id == "SG-MANIFEST-002" for f in result.findings)

    def test_npm_lifecycle_script_detected(self, tmp_path):
        (tmp_path / "package.json").write_text('{"scripts": {"postinstall": "node evil.js"}}')
        result = StaticScanner().scan(tmp_path)
        assert any(f.rule_id == "SG-MANIFEST-005" for f in result.findings)

    def test_malformed_manifest_records_incompleteness_not_crash(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("this is not [ valid toml")
        result = StaticScanner().scan(tmp_path)
        assert any(f.rule_id == "SG-MANIFEST-006" for f in result.findings)
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "MANIFEST_PARSE_ERROR" in result.incompleteness_reasons
