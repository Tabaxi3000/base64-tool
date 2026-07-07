"""
entropy.py

Shannon entropy analysis of data before and after decoding

Computes Shannon entropy on a 0-8 bits-per-byte scale, classifies it
into an interpretation band (structured, text, compressed, encrypted),
and compares the entropy of encoded input against its decoded output.
High decoded entropy signals that a payload is encrypted or compressed
rather than merely encoded, so further layer peeling is unlikely to help.

Key exports:
  EntropyReport - Frozen dataclass with input/decoded entropy and interpretation
  classify_entropy() - Maps an entropy value to a human-readable band
  is_high_entropy() - True when entropy suggests encryption/compression
  analyze_entropy() - Builds an EntropyReport from input and decoded bytes

Connects to:
  constants.py - imports ENTROPY_BANDS, HIGH_ENTROPY_THRESHOLD
  utils.py - imports shannon_entropy
  formatter.py - imports EntropyReport for display
  cli.py - imports analyze_entropy
  test_entropy.py - tests entropy math and classification
"""

from dataclasses import dataclass

from base64_tool.constants import (
    ENTROPY_BANDS,
    HIGH_ENTROPY_THRESHOLD,
)
from base64_tool.utils import shannon_entropy


@dataclass(frozen = True, slots = True)
class EntropyReport:
    input_entropy: float
    decoded_entropy: float | None
    interpretation: str
    high_entropy: bool


def classify_entropy(entropy: float) -> str:
    for lower_bound, label in ENTROPY_BANDS:
        if entropy >= lower_bound:
            return label
    return ENTROPY_BANDS[-1][1]


def is_high_entropy(entropy: float) -> bool:
    return entropy >= HIGH_ENTROPY_THRESHOLD


def analyze_entropy(
    input_data: bytes,
    decoded_data: bytes | None = None,
) -> EntropyReport:
    input_entropy = shannon_entropy(input_data)
    decoded_entropy = (
        shannon_entropy(decoded_data) if decoded_data is not None else None
    )
    reference = decoded_entropy if decoded_entropy is not None else input_entropy
    return EntropyReport(
        input_entropy = input_entropy,
        decoded_entropy = decoded_entropy,
        interpretation = classify_entropy(reference),
        high_entropy = is_high_entropy(reference),
    )
