"""
constants.py

Encoding format definitions, scoring weights, and shared constants

Defines the EncodingFormat and ExitCode enums, numeric thresholds
used by the detector (confidence, printable ratio, min input length),
character set frozensets for charset membership tests, and the
ScoreWeight class that holds every per-format confidence score
contribution. All values shared across the package live here.

Key exports:
  EncodingFormat - StrEnum of supported formats (base64, base64url, base32, hex, url, rot13, ascii85)
  ExitCode - CLI exit codes for success, error, and invalid input
  ScoreWeight - Per-format scoring weights used by detector.py
  BASE64_CHARSET, BASE64URL_CHARSET, BASE32_CHARSET, HEX_CHARSET, ASCII85_CHARSET - Valid character sets
  ENGLISH_LETTER_FREQ, COMMON_ENGLISH_WORDS - Language heuristics for ROT13 detection
  MAGIC_SIGNATURES - File-type magic-byte table for decoded output
  ENTROPY_BANDS, HIGH_ENTROPY_THRESHOLD - Shannon-entropy interpretation
  CONFIDENCE_THRESHOLD, PEEL_MAX_DEPTH, PREVIEW_LENGTH - Shared thresholds

Connects to:
  encoders.py - imports EncodingFormat
  detector.py - imports EncodingFormat, ScoreWeight, charsets, thresholds
  peeler.py - imports EncodingFormat, PEEL_MAX_DEPTH, CONFIDENCE_THRESHOLD
  formatter.py - imports EncodingFormat, CONFIDENCE_THRESHOLD, PREVIEW_LENGTH
  cli.py - imports EncodingFormat, ExitCode, PEEL_MAX_DEPTH
"""

from enum import StrEnum
from typing import Final


class EncodingFormat(StrEnum):
    BASE64 = "base64"
    BASE64URL = "base64url"
    BASE32 = "base32"
    HEX = "hex"
    URL = "url"
    ROT13 = "rot13"
    ASCII85 = "ascii85"


class ExitCode:
    SUCCESS: Final[int] = 0
    ERROR: Final[int] = 1
    INVALID_INPUT: Final[int] = 2


PEEL_MAX_DEPTH: Final[int] = 20

MIN_INPUT_LENGTH: Final[int] = 4

PREVIEW_LENGTH: Final[int] = 72

CONFIDENCE_THRESHOLD: Final[float] = 0.6

PRINTABLE_RATIO_THRESHOLD: Final[float] = 0.8


class ScoreWeight:
    DECODE_SUCCESS: Final[float] = 0.15
    PRINTABLE_RESULT: Final[float] = 0.15
    LONGER_INPUT: Final[float] = 0.05

    B64_BASE: Final[float] = 0.4
    B64_VALID_PADDING: Final[float] = 0.1
    B64_SPECIAL_CHARS: Final[float] = 0.1
    B64_MIXED_CASE: Final[float] = 0.1
    B64_NO_SIGNAL_PENALTY: Final[float] = 0.2

    B64URL_BASE: Final[float] = 0.3
    B64URL_SAFE_CHARS: Final[float] = 0.25

    B32_BASE: Final[float] = 0.35
    B32_VALID_PADDING: Final[float] = 0.1
    B32_UPPERCASE: Final[float] = 0.1

    HEX_BASE: Final[float] = 0.3
    HEX_SEPARATOR_PRESENT: Final[float] = 0.2
    HEX_ALPHA_CHARS: Final[float] = 0.1
    HEX_NO_ALPHA_PENALTY: Final[float] = 0.15
    HEX_CONSISTENT_CASE: Final[float] = 0.1
    HEX_DECODE_SUCCESS: Final[float] = 0.1

    URL_BASE: Final[float] = 0.3
    URL_RATIO_MULTIPLIER: Final[float] = 0.4
    URL_RATIO_CAP: Final[float] = 0.35
    URL_DECODE_CHANGED: Final[float] = 0.15

    ROT13_BASE: Final[float] = 0.45
    ROT13_ENGLISH_GAIN_MULTIPLIER: Final[float] = 8.0
    ROT13_ENGLISH_GAIN_CAP: Final[float] = 0.25
    ROT13_COMMON_WORDS: Final[float] = 0.15

    A85_BASE: Final[float] = 0.3
    A85_WRAPPER: Final[float] = 0.3
    A85_SPECIAL_CHARS: Final[float] = 0.1


BASE64_CHARSET: Final[
    frozenset[str]
] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

BASE64URL_CHARSET: Final[
    frozenset[str]
] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")

BASE32_CHARSET: Final[frozenset[str]] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")

HEX_CHARSET: Final[frozenset[str]] = frozenset("0123456789abcdefABCDEF")

HEX_SEPARATORS: Final[frozenset[str]] = frozenset(" :.-")

# ASCII85 uses the 85 printable characters from '!' (33) to 'u' (117),
# plus 'z' as shorthand for an all-zero group.
ASCII85_CHARSET: Final[
    frozenset[str]
] = frozenset(chr(code) for code in range(33, 118)) | {"z"}

# Punctuation that appears in ASCII85 but never in base64/base32/hex output,
# used as a distinguishing signal by the detector.
ASCII85_SPECIAL_CHARS: Final[
    frozenset[str]
] = frozenset("!\"#$%&'()*,-.:;<=>?@[\\]^_`")

ASCII85_ADOBE_PREFIX: Final[str] = "<~"
ASCII85_ADOBE_SUFFIX: Final[str] = "~>"

# Relative frequency of each letter in typical English text (percentages).
# Used by the ROT13 detector: the dot product of an observed letter
# distribution with this table peaks for genuine English and drops for
# shifted (ROT13-encoded) text.
ENGLISH_LETTER_FREQ: Final[dict[str, float]] = {
    "a": 8.2,
    "b": 1.5,
    "c": 2.8,
    "d": 4.3,
    "e": 12.7,
    "f": 2.2,
    "g": 2.0,
    "h": 6.1,
    "i": 7.0,
    "j": 0.15,
    "k": 0.77,
    "l": 4.0,
    "m": 2.4,
    "n": 6.7,
    "o": 7.5,
    "p": 1.9,
    "q": 0.095,
    "r": 6.0,
    "s": 6.3,
    "t": 9.1,
    "u": 2.8,
    "v": 0.98,
    "w": 2.4,
    "x": 0.15,
    "y": 2.0,
    "z": 0.074,
}

# Common English words used as a secondary ROT13 detection signal.
COMMON_ENGLISH_WORDS: Final[frozenset[str]] = frozenset({
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
    "for", "not", "on", "with", "he", "as", "you", "do", "at", "this",
    "but", "his", "by", "from", "they", "we", "say", "her", "she", "or",
    "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
    "is", "are", "was", "were", "been", "has", "had", "when", "over",
    "hello", "world", "secret", "message", "test", "data", "payload",
    "attack", "dawn", "quick", "brown", "fox", "lazy", "dog", "jumps",
})

# Minimum decoded English-frequency score required before the ROT13 detector
# will consider a decode to look like genuine English.
ROT13_ENGLISH_FLOOR: Final[float] = 0.045

# File-type magic-byte signatures, checked against the first bytes of decoded
# output. Each entry maps a leading byte sequence to a human name and the
# file extension to use when saving. Longer signatures are listed first so
# more specific matches win.
MAGIC_SIGNATURES: Final[tuple[tuple[bytes, str, str], ...]] = (
    (b"\x89PNG\r\n\x1a\n", "PNG image", "png"),
    (b"GIF87a", "GIF image", "gif"),
    (b"GIF89a", "GIF image", "gif"),
    (b"%PDF", "PDF document", "pdf"),
    (b"PK\x03\x04", "ZIP/DOCX/JAR archive", "zip"),
    (b"\x7fELF", "ELF executable", "elf"),
    (b"\xff\xd8\xff", "JPEG image", "jpg"),
    (b"\x1f\x8b", "gzip archive", "gz"),
    (b"BZh", "bzip2 archive", "bz2"),
    (b"\x42\x4d", "BMP image", "bmp"),
    (b"MZ", "PE executable", "exe"),
)

# Shannon-entropy interpretation bands (inclusive lower bound, label).
ENTROPY_BANDS: Final[tuple[tuple[float, str], ...]] = (
    (7.5, "encrypted or random data"),
    (6.0, "compressed data or binary format"),
    (5.0, "dense text or source code"),
    (3.0, "natural-language text"),
    (0.0, "highly structured or repetitive data"),
)

# Above this entropy, decoded output is likely encrypted/compressed rather
# than merely encoded, so further layer analysis is unlikely to help.
HIGH_ENTROPY_THRESHOLD: Final[float] = 7.5