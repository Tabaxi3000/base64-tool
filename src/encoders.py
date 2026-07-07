"""
encoders.py

Encode and decode functions for all five supported formats

Provides individual encode/decode functions for base64, base64url,
base32, hex, URL percent-encoding, ROT13, and ASCII85, plus a dispatch
registry (ENCODER_REGISTRY) that maps each EncodingFormat to its
function pair. The top-level encode(), decode(), and try_decode()
functions route calls through the registry and handle all common
decoding exceptions. Custom-alphabet base64 (encode_base64_custom /
decode_base64_custom) lives outside the registry since it needs an
extra alphabet argument.

Key exports:
  encode() - Encode bytes to string for a given format
  decode() - Decode string to bytes for a given format
  try_decode() - Like decode() but returns None on failure instead of raising
  encode_base64_custom() / decode_base64_custom() - Arbitrary-alphabet base64
  ENCODER_REGISTRY - Dict mapping EncodingFormat to (encoder, decoder) function pairs
  EncoderFn, DecoderFn - Type aliases for encoder and decoder callables

Connects to:
  constants.py - imports EncodingFormat
  detector.py - imports try_decode
  cli.py - imports encode, decode, encode_url, decode_url
  test_encoders.py - tests all functions directly
  test_properties.py - property-based roundtrip tests
  test_peeler.py - imports encode to build test inputs
"""

import base64 as b64
import binascii
from collections.abc import Callable
from urllib.parse import (
    quote,
    quote_plus,
    unquote,
    unquote_plus,
)
from base64_tool.constants import (
    ASCII85_ADOBE_PREFIX,
    ASCII85_ADOBE_SUFFIX,
    EncodingFormat,
)


type EncoderFn = Callable[[bytes], str]
type DecoderFn = Callable[[str], bytes]


def encode_base64(data: bytes) -> str:
    return b64.b64encode(data).decode("ascii")


def decode_base64(data: str) -> bytes:
    cleaned = "".join(data.split())
    return b64.b64decode(cleaned, validate=True)


def encode_base64url(data: bytes) -> str:
    return b64.urlsafe_b64encode(data).decode("ascii")


def decode_base64url(data: str) -> bytes:
    cleaned = "".join(data.split())
    return b64.urlsafe_b64decode(cleaned)


def encode_base32(data: bytes) -> str:
    return b64.b32encode(data).decode("ascii")


def decode_base32(data: str) -> bytes:
    cleaned = "".join(data.split()).upper()
    return b64.b32decode(cleaned)


def encode_hex(data: bytes) -> str:
    return data.hex()


def decode_hex(data: str) -> bytes:
    cleaned = data.strip()
    for sep in (" ", ":", "-", "."):
        cleaned = cleaned.replace(sep, "")
    return bytes.fromhex(cleaned)


# ROT13 rotates each ASCII letter by 13 places and is its own inverse, so the
# same translation table serves for both encoding and decoding. latin-1 maps
# every byte 1:1 to a code point, keeping non-letter bytes lossless.
_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def encode_rot13(data: bytes) -> str:
    return data.decode("latin-1").translate(_ROT13_TABLE)


def decode_rot13(data: str) -> bytes:
    return data.translate(_ROT13_TABLE).encode("latin-1")


def encode_ascii85(data: bytes) -> str:
    return b64.a85encode(data).decode("ascii")


def decode_ascii85(data: str) -> bytes:
    cleaned = "".join(data.split())
    adobe = cleaned.startswith(ASCII85_ADOBE_PREFIX) and cleaned.endswith(
        ASCII85_ADOBE_SUFFIX
    )
    return b64.a85decode(cleaned, adobe = adobe)


def _split_alphabet(alphabet: str) -> tuple[str, str]:
    if len(alphabet) == 65:
        alpha, pad = alphabet[: 64], alphabet[64]
    elif len(alphabet) == 64:
        alpha, pad = alphabet, "="
    else:
        raise ValueError(
            "Custom alphabet must be 64 characters "
            f"(or 65 with a padding character), got {len(alphabet)}"
        )
    if len(set(alpha)) != 64:
        raise ValueError("Custom alphabet must contain 64 distinct characters")
    return alpha, pad


def encode_base64_custom(data: bytes, alphabet: str) -> str:
    alpha, pad = _split_alphabet(alphabet)
    out: list[str] = []

    for i in range(0, len(data), 3):
        chunk = data[i: i + 3]
        n = len(chunk)
        padded = chunk + b"\x00" * (3 - n)
        value = (padded[0] << 16) | (padded[1] << 8) | padded[2]
        sextets = [
            (value >> 18) & 0x3F,
            (value >> 12) & 0x3F,
            (value >> 6) & 0x3F,
            value & 0x3F,
        ]
        chars = [alpha[s] for s in sextets[: n + 1]]
        chars.extend(pad * (4 - len(chars)))
        out.append("".join(chars))

    return "".join(out)


def decode_base64_custom(data: str, alphabet: str) -> bytes:
    alpha, pad = _split_alphabet(alphabet)
    lookup = {char: index for index, char in enumerate(alpha)}
    cleaned = "".join(data.split()).rstrip(pad)
    out = bytearray()

    for i in range(0, len(cleaned), 4):
        group = cleaned[i: i + 4]
        if len(group) == 1:
            raise ValueError("Invalid custom-base64 length")
        try:
            sextets = [lookup[char] for char in group]
        except KeyError as exc:
            raise ValueError(
                f"Character {exc.args[0]!r} is not in the custom alphabet"
            ) from None
        acc = 0
        for sextet in sextets:
            acc = (acc << 6) | sextet
        acc <<= 6 * (4 - len(group))
        chunk = acc.to_bytes(3, "big")
        out.extend(chunk[: len(group) - 1])

    return bytes(out)


def encode_url(data: bytes, *, form: bool = False) -> str:
    text = data.decode("utf-8")
    if form:
        return quote_plus(text)
    return quote(text, safe="")


def decode_url(data: str, *, form: bool = False) -> bytes:
    if form:
        return unquote_plus(data).encode("utf-8")
    return unquote(data).encode("utf-8")


ENCODER_REGISTRY: dict[
    EncodingFormat,
    tuple[EncoderFn, DecoderFn],
] = {
    EncodingFormat.BASE64: (encode_base64, decode_base64),
    EncodingFormat.BASE64URL: (encode_base64url, decode_base64url),
    EncodingFormat.BASE32: (encode_base32, decode_base32),
    EncodingFormat.HEX: (encode_hex, decode_hex),
    EncodingFormat.URL: (
        lambda data: encode_url(data),
        lambda data: decode_url(data),
    ),
    EncodingFormat.ROT13: (encode_rot13, decode_rot13),
    EncodingFormat.ASCII85: (encode_ascii85, decode_ascii85),
}


def encode(data: bytes, fmt: EncodingFormat) -> str:
    encoder_fn, _ = ENCODER_REGISTRY[fmt]
    return encoder_fn(data)


def decode(data: str, fmt: EncodingFormat) -> bytes:
    _, decoder_fn = ENCODER_REGISTRY[fmt]
    return decoder_fn(data)


def try_decode(data: str, fmt: EncodingFormat) -> bytes | None:
    try:
        return decode(data, fmt)
    except (
        ValueError,
        binascii.Error,
        UnicodeDecodeError,
        UnicodeEncodeError,
    ):
        return None