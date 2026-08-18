"""Regression tests for SG2-006 (P3): invalid UTF-8 in captured dynamic
stdout/stderr was decoded lossily (errors="replace") but the final
DynamicResult still reported COMPLETE, silently claiming a byte-for-byte
observation that did not actually happen.

Real-subprocess tests exercise CommandRunner/DynamicObserver end-to-end
with a target that writes genuinely invalid UTF-8 bytes to its own
stdout/stderr file descriptors (bypassing Python's own text-mode
encoding, which would refuse to write invalid UTF-8 itself). Unit-level
tests exercise _BoundedStreamCapture directly for the truncation-
interaction and split-valid-multibyte-character edge cases, which are
impractical to force deterministically through a real OS pipe.
"""

from __future__ import annotations

import sys
from pathlib import Path

import skillguard.dynamic.runner as runner_mod
from skillguard.dynamic.observer import DynamicObserver, DynamicRunConfig
from skillguard.dynamic.runner import EnvironmentPolicy
from skillguard.models import AnalysisStatus
from skillguard.paths import BoundRoot

FIXTURES = Path(__file__).parent / "fixtures"


def _run(target_dir: Path, argv: list[str], **kwargs) -> object:
    root = BoundRoot.bind(target_dir)
    config = DynamicRunConfig(
        argv=tuple(argv),
        timeout=kwargs.pop("timeout", 15.0),
        env_policy=kwargs.pop("env_policy", EnvironmentPolicy()),
        **kwargs,
    )
    return DynamicObserver(config).run(root)


class TestInvalidUtf8EndToEnd:
    def test_invalid_stdout_marks_encoding_loss_not_complete(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'before\\xff\\xfeafter'); sys.stdout.buffer.flush()",
            ],
        )
        assert "OUTPUT_ENCODING_LOSS" in result.incompleteness_reasons
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "before" in result.command_result.stdout
        assert "after" in result.command_result.stdout
        assert "�" in result.command_result.stdout

    def test_invalid_stderr_marks_encoding_loss_not_complete(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.buffer.write(b'\\xff\\xfe'); sys.stderr.buffer.flush()",
            ],
        )
        assert "OUTPUT_ENCODING_LOSS" in result.incompleteness_reasons
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE

    def test_invalid_both_streams_marks_encoding_loss(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "sys.stdout.buffer.write(b'\\xff'); sys.stdout.buffer.flush(); "
                    "sys.stderr.buffer.write(b'\\xfe'); sys.stderr.buffer.flush()"
                ),
            ],
        )
        assert "OUTPUT_ENCODING_LOSS" in result.incompleteness_reasons
        assert any(
            "stdout" in e.summary and "stderr" in e.summary
            for e in result.evidence
            if e.origin == "dynamic.output" and "invalid UTF-8" in e.summary
        )

    def test_valid_output_no_encoding_loss(self, tmp_path):
        """Writes explicitly UTF-8-encoded bytes via the buffer interface
        rather than print() -- print()'s encoding on Windows can follow
        the legacy console codepage rather than UTF-8 when not attached
        to a real console, which would make this test's own fixture
        produce invalid bytes for reasons unrelated to what's being
        tested here."""
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write('perfectly valid ascii and utf8 é'.encode('utf-8')); sys.stdout.buffer.flush()",
            ],
        )
        assert "OUTPUT_ENCODING_LOSS" not in result.incompleteness_reasons
        assert result.status == AnalysisStatus.COMPLETE
        assert "é" in result.command_result.stdout

    def test_large_valid_multibyte_output_spanning_real_chunk_boundaries_not_flagged(
        self, tmp_path
    ):
        """Real subprocess, real OS pipe, output large enough to span
        multiple 65536-byte reader chunks, made entirely of a repeating
        multi-byte UTF-8 character so a naive per-chunk decode would be
        very likely to split one somewhere. Must NOT be flagged lossy."""
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(('é' * 200_000).encode('utf-8')); sys.stdout.buffer.flush()",
            ],
            timeout=20.0,
        )
        assert "OUTPUT_ENCODING_LOSS" not in result.incompleteness_reasons
        assert "�" not in result.command_result.stdout


class TestBoundedStreamCaptureUnitLevel:
    """Direct tests of _BoundedStreamCapture for interactions
    impractical to force deterministically through a real OS pipe."""

    def _capture_from_chunks(self, chunks: list[bytes], max_bytes: int):
        chunks_iter = iter([*chunks, b""])

        class ChunkedStream:
            def read(self, _size):
                return next(chunks_iter)

            def close(self):
                return None

        cap = runner_mod._BoundedStreamCapture(ChunkedStream(), max_bytes)
        cap.start()
        cap.join()
        return cap.result()

    def test_invalid_bytes_near_output_cap(self):
        # 8-byte cap; the invalid byte lands right at the edge.
        text, truncated, lossy = self._capture_from_chunks([b"1234567" + b"\xff"], max_bytes=8)
        assert lossy is True

    def test_invalid_bytes_plus_truncation_both_reasons_independently_true(self):
        # The invalid byte sits WITHIN the first max_bytes (so it survives
        # _drain's own byte-cap accumulation and is still in the buffer
        # result() decodes), while there is more valid data beyond the
        # cap that gets dropped -- both truncated AND lossy must be
        # observable together, neither suppressing the other.
        text, truncated, lossy = self._capture_from_chunks(
            [b"\xff" + b"AAAA" + b"BBBBBBBBBBBBBBBB"], max_bytes=5
        )
        assert truncated is True
        assert lossy is True

    def test_valid_multibyte_character_split_across_reader_chunks_not_lossy(self):
        # 'é' is b'\xc3\xa9' in UTF-8 -- split the two bytes across two
        # separate read() calls/chunks, exactly the scenario a naive
        # per-chunk decode would misclassify as invalid.
        text, truncated, lossy = self._capture_from_chunks(
            [b"before-", b"\xc3", b"\xa9", b"-after"], max_bytes=10_000
        )
        assert lossy is False
        assert text == "before-é-after"

    def test_valid_output_under_cap_not_lossy(self):
        text, truncated, lossy = self._capture_from_chunks([b"hello world"], max_bytes=10_000)
        assert lossy is False
        assert truncated is False
        assert text == "hello world"

    def test_only_invalid_bytes_no_valid_content_still_lossy_not_crashing(self):
        text, truncated, lossy = self._capture_from_chunks([b"\xff\xfe\xfd"], max_bytes=10_000)
        assert lossy is True
        assert "�" in text
