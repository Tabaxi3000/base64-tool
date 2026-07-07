"""
test_entropy.py

Tests for Shannon entropy math and classification in entropy.py

Verifies the entropy of known inputs (all-zeros is 0, uniform bytes is
8), band classification, the high-entropy flag, and that analyze_entropy
compares input against decoded output and picks the decoded band.

Tests:
  TestShannonEntropy - boundary values and monotonic behavior
  TestClassify - band labels and high-entropy flag
  TestAnalyzeEntropy - report fields for encoded vs decoded data

Connects to:
  entropy.py - functions under test
  utils.py - imports shannon_entropy
"""

import pytest

from base64_tool.entropy import (
    analyze_entropy,
    classify_entropy,
    is_high_entropy,
)
from base64_tool.utils import shannon_entropy


class TestShannonEntropy:
    def test_empty_is_zero(self) -> None:
        """
        Checks that empty data has zero entropy
        """
        assert shannon_entropy(b"") == 0.0

    def test_single_value_is_zero(self) -> None:
        """
        Checks that a run of one repeated byte has zero entropy
        """
        assert shannon_entropy(b"\x00" * 100) == 0.0

    def test_all_byte_values_is_eight(self) -> None:
        """
        Checks that a uniform distribution over all 256 bytes has entropy 8
        """
        assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)

    def test_two_equal_symbols_is_one(self) -> None:
        """
        Checks that two equally likely byte values give entropy 1
        """
        assert shannon_entropy(b"AB" * 50) == pytest.approx(1.0)


class TestClassify:
    def test_random_band(self) -> None:
        """
        Checks that maximum entropy classifies as encrypted/random
        """
        assert "encrypted" in classify_entropy(7.9)

    def test_text_band(self) -> None:
        """
        Checks that mid-range entropy classifies as natural-language text
        """
        assert "text" in classify_entropy(3.5)

    def test_structured_band(self) -> None:
        """
        Checks that very low entropy classifies as structured/repetitive
        """
        assert "structured" in classify_entropy(0.2)

    def test_high_entropy_flag(self) -> None:
        """
        Checks that the high-entropy flag trips at the threshold
        """
        assert is_high_entropy(7.9) is True
        assert is_high_entropy(4.0) is False


class TestAnalyzeEntropy:
    def test_reports_both_stages(self) -> None:
        """
        Checks that analyze_entropy records input and decoded entropy separately
        """
        report = analyze_entropy(b"AAAAAAAA", bytes(range(256)))
        assert report.input_entropy == pytest.approx(0.0)
        assert report.decoded_entropy == pytest.approx(8.0)
        assert report.high_entropy is True

    def test_interpretation_uses_decoded(self) -> None:
        """
        Checks that the interpretation is based on the decoded data when present
        """
        report = analyze_entropy(b"abcd", bytes(range(256)))
        assert "encrypted" in report.interpretation

    def test_no_decoded_uses_input(self) -> None:
        """
        Checks that without decoded data the report falls back to the input
        """
        report = analyze_entropy(b"\x00" * 64, None)
        assert report.decoded_entropy is None
        assert "structured" in report.interpretation
