"""
analyze.py

Bulk detection statistics over a file of encoded samples

Runs the detector over every line of an input file and aggregates the
results: which formats appear, how confident detection was per format,
how many samples matched nothing, and which samples matched more than
one format (ambiguous indicators). Built for triaging bulk IOC lists.

Key exports:
  SampleResult - Per-line result: best format, all matches, ambiguity flag
  AnalysisReport - Aggregate counts, per-format averages, and per-sample rows
  analyze_samples() - Builds an AnalysisReport from an iterable of lines
  report_to_dict() - Serializes an AnalysisReport to a JSON-ready dict

Connects to:
  constants.py - imports EncodingFormat
  detector.py - imports detect_encoding
  formatter.py - imports AnalysisReport for display
  cli.py - imports analyze_samples, report_to_dict
  test_analyze.py - tests aggregation and ambiguity detection
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from base64_tool.constants import EncodingFormat
from base64_tool.detector import detect_encoding


@dataclass(frozen = True, slots = True)
class SampleResult:
    line_number: int
    sample: str
    matches: tuple[tuple[EncodingFormat, float], ...]

    @property
    def best_format(self) -> EncodingFormat | None:
        return self.matches[0][0] if self.matches else None

    @property
    def best_confidence(self) -> float:
        return self.matches[0][1] if self.matches else 0.0

    @property
    def ambiguous(self) -> bool:
        return len(self.matches) > 1


@dataclass(frozen = True, slots = True)
class AnalysisReport:
    total: int
    detected: int
    failures: int
    ambiguous: int
    format_counts: dict[EncodingFormat, int]
    format_avg_confidence: dict[EncodingFormat, float]
    samples: tuple[SampleResult, ...]


def analyze_samples(lines: Iterable[str]) -> AnalysisReport:
    samples: list[SampleResult] = []
    format_counts: dict[EncodingFormat, int] = {}
    confidence_totals: dict[EncodingFormat, float] = {}
    detected = 0
    ambiguous = 0

    line_number = 0
    for raw_line in lines:
        sample = raw_line.strip()
        if not sample:
            continue
        line_number += 1

        results = detect_encoding(sample)
        matches = tuple((r.format, r.confidence) for r in results)
        result = SampleResult(
            line_number = line_number,
            sample = sample,
            matches = matches,
        )
        samples.append(result)

        best = result.best_format
        if best is not None:
            detected += 1
            format_counts[best] = format_counts.get(best, 0) + 1
            confidence_totals[best] = (
                confidence_totals.get(best, 0.0) + result.best_confidence
            )
        if result.ambiguous:
            ambiguous += 1

    format_avg_confidence = {
        fmt: confidence_totals[fmt] / count
        for fmt, count in format_counts.items()
    }

    total = len(samples)
    return AnalysisReport(
        total = total,
        detected = detected,
        failures = total - detected,
        ambiguous = ambiguous,
        format_counts = format_counts,
        format_avg_confidence = format_avg_confidence,
        samples = tuple(samples),
    )


def report_to_dict(report: AnalysisReport) -> dict[str, Any]:
    return {
        "total": report.total,
        "detected": report.detected,
        "failures": report.failures,
        "ambiguous": report.ambiguous,
        "format_distribution": {
            fmt.value: count for fmt, count in report.format_counts.items()
        },
        "average_confidence": {
            fmt.value: round(avg, 2)
            for fmt, avg in report.format_avg_confidence.items()
        },
        "samples": [
            {
                "line": sample.line_number,
                "sample": sample.sample,
                "best_format": (
                    sample.best_format.value
                    if sample.best_format is not None
                    else None
                ),
                "confidence": round(sample.best_confidence, 2),
                "ambiguous": sample.ambiguous,
                "matches": [
                    {"format": fmt.value, "confidence": round(conf, 2)}
                    for fmt, conf in sample.matches
                ],
            }
            for sample in report.samples
        ],
    }
