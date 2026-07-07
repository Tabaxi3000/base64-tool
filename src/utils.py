"""
utils.py

Input resolution and string/bytes utility functions

Handles the three input sources the CLI accepts: a positional
argument, a --file path, or piped stdin. Also provides truncate()
for capping display strings, safe_bytes_preview() for converting
raw bytes to a readable preview, and is_printable_text() for
checking whether decoded bytes look like human-readable output.

Key exports:
  resolve_input_bytes() - Returns raw bytes from argument, file, or stdin
  resolve_input_text() - Returns decoded text from argument, file, or stdin
  truncate() - Truncates a string with "..." if it exceeds the length limit
  safe_bytes_preview() - Converts bytes to UTF-8 string or hex fallback
  is_printable_text() - Returns True if bytes decode to mostly printable characters
  english_letter_score() - Letter-frequency similarity to English (ROT13 detection)
  common_word_ratio() - Fraction of tokens that are common English words
  shannon_entropy() - Shannon entropy of bytes on a 0-8 scale

Connects to:
  constants.py - imports ENGLISH_LETTER_FREQ, COMMON_ENGLISH_WORDS
  detector.py - imports is_printable_text, english_letter_score, common_word_ratio
  peeler.py - imports safe_bytes_preview, truncate
  formatter.py - imports safe_bytes_preview
  entropy.py - imports shannon_entropy
  cli.py - imports resolve_input_bytes, resolve_input_text
"""

import math
import re
import sys
from collections import Counter
from pathlib import Path

import typer

from base64_tool.constants import (
    COMMON_ENGLISH_WORDS,
    ENGLISH_LETTER_FREQ,
)


_NORMALIZED_ENGLISH_FREQ: dict[str, float] = {
    letter: weight / sum(ENGLISH_LETTER_FREQ.values())
    for letter, weight in ENGLISH_LETTER_FREQ.items()
}

_WORD_PATTERN = re.compile(r"[a-z]+")


def resolve_input_bytes(
    data: str | None,
    file: Path | None,
) -> bytes:
    if file is not None:
        if not file.exists():
            raise typer.BadParameter(f"File not found: {file}")
        return file.read_bytes()
    if data is not None:
        return data.encode("utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    raise typer.BadParameter(
        "No input provided. Pass an argument, use --file, or pipe stdin."
    )


def resolve_input_text(
    data: str | None,
    file: Path | None,
) -> str:
    if file is not None:
        if not file.exists():
            raise typer.BadParameter(f"File not found: {file}")
        return file.read_text("utf-8").strip()
    if data is not None:
        return data.strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    raise typer.BadParameter(
        "No input provided. Pass an argument, use --file, or pipe stdin."
    )


def truncate(text: str, length: int = 72) -> str:
    if len(text) <= length:
        return text
    return text[: length] + "..."


def safe_bytes_preview(data: bytes, length: int = 72) -> str:
    try:
        text = data.decode("utf-8")
        return truncate(text, length)
    except (UnicodeDecodeError, ValueError):
        return truncate(data.hex(), length)


def is_printable_text(data: bytes, threshold: float = 0.8) -> bool:
    try:
        text = data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return False
    if not text:
        return False
    printable_count = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return (printable_count / len(text)) >= threshold


def english_letter_score(text: str) -> float:
    """
    Dot product of the text's letter distribution with English letter
    frequencies. Peaks (~0.065) for genuine English and drops (~0.038) for
    ROT13-shifted or random letters, so a rise after decoding signals ROT13.
    """
    counts = Counter(char for char in text.lower() if "a" <= char <= "z")
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return sum(
        (counts[letter] / total) * weight
        for letter, weight in _NORMALIZED_ENGLISH_FREQ.items()
    )


def common_word_ratio(text: str) -> float:
    """
    Fraction of whitespace-delimited word tokens that are common English words.
    """
    words = _WORD_PATTERN.findall(text.lower())
    if not words:
        return 0.0
    matches = sum(1 for word in words if word in COMMON_ENGLISH_WORDS)
    return matches / len(words)


def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy of a byte string on a 0-8 scale (bits per byte).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy