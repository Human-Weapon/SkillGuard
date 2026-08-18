"""Regression tests for SG3-004 (P3, third Daybreak adversarial audit):
_BoundedStreamCapture.result() computed encoding_lossy by decoding with
errors="replace" and then checking whether the literal U+FFFD character
appeared in the RESULT text. That conflates three distinct situations:
(A) the target emitted genuinely invalid UTF-8 bytes, (B) the target
legitimately emitted the valid 3-byte UTF-8 encoding of U+FFFD itself
(EF BF BD is perfectly valid UTF-8), and (C) SkillGuard's own retention
cap (or the stream simply ending) bisected a valid multibyte character.
Only (A) should ever set encoding_lossy; (B) must not, and (C) is
truncation, not encoding loss.

Real subprocess tests exercise CommandRunner/DynamicObserver end-to-end;
unit-level tests exercise _decode_captured_bytes/_BoundedStreamCapture
directly for cases (near-cap boundaries, chunk-vs-cap interaction)
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


class TestLegitimateFffdNotLossyEndToEnd:
    def test_valid_literal_fffd_alone_not_lossy(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'\\xef\\xbf\\xbd'); sys.stdout.buffer.flush()",
            ],
        )
        assert "OUTPUT_ENCODING_LOSS" not in result.incompleteness_reasons
        assert result.status == AnalysisStatus.COMPLETE
        assert result.command_result.stdout == "�"

    def test_text_containing_valid_literal_fffd_not_lossy(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'before\\xef\\xbf\\xbdafter'); sys.stdout.buffer.flush()",
            ],
        )
        assert "OUTPUT_ENCODING_LOSS" not in result.incompleteness_reasons
        assert result.command_result.stdout == "before�after"

    def test_multiple_valid_literal_fffd_not_lossy(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'\\xef\\xbf\\xbd' * 5); sys.stdout.buffer.flush()",
            ],
        )
        assert "OUTPUT_ENCODING_LOSS" not in result.incompleteness_reasons
        assert result.command_result.stdout == "�" * 5

    def test_genuinely_invalid_bytes_still_lossy(self, tmp_path):
        """Confirm the fix didn't overcorrect: real invalid bytes must
        still be flagged, exactly like SG2-006 already verified."""
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'\\xff\\xfe'); sys.stdout.buffer.flush()",
            ],
        )
        assert "OUTPUT_ENCODING_LOSS" in result.incompleteness_reasons
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE


class TestCapSplitMultibyteNotAutomaticallyLossy:
    def test_valid_multibyte_bisected_by_max_output_bytes_not_lossy(self, tmp_path):
        """15 ASCII bytes + a 3-byte EURO SIGN, capped at 16 bytes --
        the cap lands exactly inside the multibyte sequence. This must
        be OUTPUT_TRUNCATED, not OUTPUT_ENCODING_LOSS: the original
        stream was entirely valid UTF-8."""
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(('x' * 15).encode() + '€'.encode('utf-8')); sys.stdout.buffer.flush()",
            ],
            max_output_bytes=16,
        )
        assert "OUTPUT_TRUNCATED" in result.incompleteness_reasons
        assert "OUTPUT_ENCODING_LOSS" not in result.incompleteness_reasons
        assert result.command_result.stdout.startswith("x" * 15)


class TestDecodeCapturedBytesUnitLevel:
    """Direct tests of _decode_captured_bytes for combinations
    impractical to force deterministically through a real OS pipe."""

    def test_valid_fffd_near_cap(self):
        data = b"x" * 5 + b"\xef\xbf\xbd"
        text, lossy = runner_mod._decode_captured_bytes(data)
        assert lossy is False
        assert text == "x" * 5 + "�"

    def test_invalid_byte_in_middle_is_lossy(self):
        data = b"hello \xc3\x28 world"  # invalid continuation byte
        text, lossy = runner_mod._decode_captured_bytes(data)
        assert lossy is True
        assert "�" in text
        assert text.startswith("hello ")
        assert text.endswith(" world")

    def test_invalid_bytes_plus_truncation_combo(self):
        """Invalid byte survives the byte cap (still in the retained
        buffer), AND the buffer's own tail is also cut mid-character --
        both must be independently observable: lossy from the invalid
        byte, and the caller separately tracks truncated."""
        data = b"\xff" + b"y" * 10 + "€".encode()[:2]
        text, lossy = runner_mod._decode_captured_bytes(data)
        assert lossy is True  # the invalid \xff, not the trailing cut

    def test_empty_buffer_not_lossy(self):
        text, lossy = runner_mod._decode_captured_bytes(b"")
        assert text == ""
        assert lossy is False

    def test_only_trailing_incomplete_sequence_at_true_eof_is_lossy(self):
        # First two bytes of a 3-byte euro sign at true EOF are malformed.
        data = "€".encode()[:2]
        text, lossy = runner_mod._decode_captured_bytes(data)
        assert lossy is True
        assert "�" in text  # still safely displayable

    def test_trailing_incomplete_sequence_cut_by_capture_cap_is_not_lossy(self):
        data = "€".encode()[:2]
        text, lossy = runner_mod._decode_captured_bytes(data, capture_truncated=True)
        assert lossy is False
        assert "�" in text

    def test_valid_multibyte_split_across_reader_chunks_not_lossy(self):
        """Exercises the full _BoundedStreamCapture, not just the
        decode helper: 'é' (b'\\xc3\\xa9') split across two separate
        read() calls/chunks -- the scenario SG2-006 already protects
        against chunk-boundary misclassification for; confirms SG3-004's
        change didn't regress it."""
        chunks_iter = iter([b"before-", b"\xc3", b"\xa9", b"-after", b""])

        class ChunkedStream:
            def read(self, _size):
                return next(chunks_iter)

            def close(self):
                return None

        cap = runner_mod._BoundedStreamCapture(ChunkedStream(), 10_000)
        cap.start()
        cap.join()
        text, truncated, lossy = cap.result()
        assert lossy is False
        assert truncated is False
        assert text == "before-é-after"
