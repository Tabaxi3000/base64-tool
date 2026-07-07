"""
test_analyze.py

Tests for bulk detection statistics in analyze.py

Verifies that analyze_samples aggregates format counts and per-format
average confidence, counts detection failures, flags samples that match
more than one format, skips blank lines, and that report_to_dict
produces a JSON-ready structure.

Tests:
  TestAnalyzeSamples - counts, failures, blank-line skipping, averages
  TestAmbiguity - ambiguous flag for multi-format samples
  TestReportToDict - serialized report shape

Connects to:
  analyze.py - functions under test
  constants.py - imports EncodingFormat
"""

from base64_tool.analyze import analyze_samples, report_to_dict
from base64_tool.constants import EncodingFormat


SAMPLES = [
    "SGVsbG8gV29ybGQ=",
    "48656c6c6f20576f726c64",
    "JBSWY3DPEBLW64TMMQ======",
    "this is plain text with no encoding",
]


class TestAnalyzeSamples:
    def test_counts_totals(self) -> None:
        """
        Checks total, detected, and failure counts for a mixed sample set
        """
        report = analyze_samples(SAMPLES)
        assert report.total == 4
        assert report.detected == 3
        assert report.failures == 1

    def test_format_distribution(self) -> None:
        """
        Checks that each encoded sample is counted under its best format
        """
        report = analyze_samples(SAMPLES)
        assert report.format_counts.get(EncodingFormat.BASE64) == 1
        assert report.format_counts.get(EncodingFormat.HEX) == 1
        assert report.format_counts.get(EncodingFormat.BASE32) == 1

    def test_blank_lines_skipped(self) -> None:
        """
        Checks that blank and whitespace-only lines are ignored
        """
        report = analyze_samples(["SGVsbG8gV29ybGQ=", "", "   ", "\t"])
        assert report.total == 1

    def test_average_confidence_in_range(self) -> None:
        """
        Checks that per-format average confidence is a probability in [0, 1]
        """
        report = analyze_samples(SAMPLES)
        for avg in report.format_avg_confidence.values():
            assert 0.0 <= avg <= 1.0


class TestAmbiguity:
    def test_single_format_not_ambiguous(self) -> None:
        """
        Checks that a hex string matching only hex is not flagged ambiguous
        """
        report = analyze_samples(["48656c6c6f20576f726c64"])
        assert report.ambiguous == 0
        assert report.samples[0].ambiguous is False

    def test_ambiguous_counts_multi_format(self) -> None:
        """
        Checks that samples matching more than one format are flagged ambiguous
        """
        # A base64 string that also satisfies the base64url charset commonly
        # matches both formats.
        report = analyze_samples(["dGVzdC1kYXRhX3ZhbHVl"])
        sample = report.samples[0]
        if len(sample.matches) > 1:
            assert sample.ambiguous is True
            assert report.ambiguous >= 1


class TestReportToDict:
    def test_serialized_shape(self) -> None:
        """
        Checks that report_to_dict exposes the expected top-level keys
        """
        data = report_to_dict(analyze_samples(SAMPLES))
        assert set(data) >= {
            "total",
            "detected",
            "failures",
            "ambiguous",
            "format_distribution",
            "average_confidence",
            "samples",
        }
        assert len(data["samples"]) == 4
        assert data["samples"][0]["line"] == 1
