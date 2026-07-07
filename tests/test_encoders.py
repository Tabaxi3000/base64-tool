"""
test_encoders.py

Unit tests for all encoder and decoder functions in encoders.py

Tests each format with known-good inputs, full roundtrips, whitespace
tolerance in decoders, binary and unicode data, and invalid input
rejection. Also covers the ENCODER_REGISTRY dispatch via encode() and
decode(), and the try_decode() safe wrapper.

Tests:
  TestBase64 - encode, decode, roundtrip, whitespace, binary, unicode, invalid input
  TestBase64Url - URL-safe character guarantees and roundtrip
  TestBase32 - encode, decode, lowercase tolerance, padding
  TestHex - encode, decode, colon/space/dash separator variants
  TestUrl - percent-encoding, form-encoding (plus signs), roundtrip
  TestRegistryDispatch - parametrized roundtrip for all formats, try_decode

Connects to:
  encoders.py - all functions under test
  constants.py - imports EncodingFormat
"""

import base64 as b64
import binascii

import pytest

from base64_tool.constants import EncodingFormat
from base64_tool.encoders import (
    decode,
    decode_ascii85,
    decode_base32,
    decode_base64,
    decode_base64_custom,
    decode_base64url,
    decode_hex,
    decode_rot13,
    decode_url,
    encode,
    encode_ascii85,
    encode_base32,
    encode_base64,
    encode_base64_custom,
    encode_base64url,
    encode_hex,
    encode_rot13,
    encode_url,
    try_decode,
)


REVERSED_ALPHABET = (
    "ZYXWVUTSRQPONMLKJIHGFEDCBA"
    "zyxwvutsrqponmlkjihgfedcba"
    "9876543210+/"
)
STANDARD_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/"
)


class TestBase64:
    def test_encode_simple_text(self) -> None:
        """
        Checks that 'Hello World' encodes to the known base64 string
        """
        assert encode_base64(b"Hello World") == "SGVsbG8gV29ybGQ="

    def test_decode_simple_text(self) -> None:
        """
        Checks that a known base64 string decodes back to 'Hello World'
        """
        assert decode_base64("SGVsbG8gV29ybGQ=") == b"Hello World"

    def test_roundtrip(self) -> None:
        """
        Encodes then decodes an ASCII sentence and checks it matches the original
        """
        original = b"The quick brown fox jumps over the lazy dog"
        assert decode_base64(encode_base64(original)) == original

    def test_encode_empty(self) -> None:
        """
        Checks that encoding empty bytes produces an empty string
        """
        assert encode_base64(b"") == ""

    def test_decode_empty(self) -> None:
        """
        Checks that decoding an empty string produces empty bytes
        """
        assert decode_base64("") == b""

    def test_encode_binary_data(self) -> None:
        """
        Encodes all 256 byte values and checks the roundtrip is lossless
        """
        data = bytes(range(256))
        assert decode_base64(encode_base64(data)) == data

    def test_decode_with_whitespace(self) -> None:
        """
        Checks that a base64 string split across newlines still decodes correctly
        """
        encoded = "SGVs\nbG8g\nV29y\nbGQ="
        assert decode_base64(encoded) == b"Hello World"

    def test_decode_invalid_raises(self) -> None:
        """
        Checks that decoding garbage characters raises an exception
        """
        with pytest.raises((ValueError, binascii.Error)):
            decode_base64("!!!invalid!!!")

    def test_encode_unicode(self) -> None:
        """
        Checks that multi-byte unicode survives a base64 roundtrip
        """
        data = "Hello 世界".encode()
        decoded = decode_base64(encode_base64(data))
        assert decoded == data


class TestBase64Url:
    def test_encode_with_url_chars(self) -> None:
        """
        Checks that URL-safe base64 never emits + or / characters
        """
        data = b"\xfb\xff\xfe"
        encoded = encode_base64url(data)
        assert "+" not in encoded
        assert "/" not in encoded

    def test_decode_url_safe(self) -> None:
        """
        Checks that data containing / and + round-trips through URL-safe base64
        """
        result = decode_base64url(encode_base64url(b"test/path+query"))
        assert result == b"test/path+query"

    def test_roundtrip(self) -> None:
        """
        Encodes then decodes a URL string and checks it matches the original
        """
        original = b"https://example.com?token=abc+def/ghi"
        assert decode_base64url(encode_base64url(original)) == original


class TestBase32:
    def test_encode_simple(self) -> None:
        """
        Checks that 'Hello' encodes to its known base32 representation
        """
        assert encode_base32(b"Hello") == "JBSWY3DP"

    def test_decode_simple(self) -> None:
        """
        Checks that a known base32 string decodes to 'Hello'
        """
        assert decode_base32("JBSWY3DP") == b"Hello"

    def test_roundtrip(self) -> None:
        """
        Encodes then decodes a short sentence and checks it matches the original
        """
        original = b"Base32 encoding test"
        assert decode_base32(encode_base32(original)) == original

    def test_decode_lowercase_accepted(self) -> None:
        """
        Checks that lowercase base32 input is accepted and decoded correctly
        """
        assert decode_base32("jbswy3dp") == b"Hello"

    def test_decode_with_padding(self) -> None:
        """
        Checks that a padded base32 string decodes to 'Hello World'
        """
        assert decode_base32("JBSWY3DPEBLW64TMMQ======") == b"Hello World"


class TestHex:
    def test_encode_simple(self) -> None:
        """
        Checks that bytes \\xca\\xfe encode to the hex string 'cafe'
        """
        assert encode_hex(b"\xca\xfe") == "cafe"

    def test_decode_simple(self) -> None:
        """
        Checks that 'cafe' decodes to the bytes \\xca\\xfe
        """
        assert decode_hex("cafe") == b"\xca\xfe"

    def test_decode_with_colons(self) -> None:
        """
        Checks that colon-separated hex decodes correctly
        """
        assert decode_hex("ca:fe:ba:be") == b"\xca\xfe\xba\xbe"

    def test_decode_with_spaces(self) -> None:
        """
        Checks that space-separated hex decodes correctly
        """
        assert decode_hex("ca fe ba be") == b"\xca\xfe\xba\xbe"

    def test_decode_with_dashes(self) -> None:
        """
        Checks that dash-separated hex decodes correctly
        """
        assert decode_hex("ca-fe-ba-be") == b"\xca\xfe\xba\xbe"

    def test_decode_uppercase(self) -> None:
        """
        Checks that uppercase hex input decodes correctly
        """
        assert decode_hex("CAFE") == b"\xca\xfe"

    def test_roundtrip(self) -> None:
        """
        Encodes then decodes a known string and checks no data is lost
        """
        original = b"Hello World"
        assert decode_hex(encode_hex(original)) == original


class TestUrl:
    def test_encode_special_chars(self) -> None:
        """
        Checks that spaces and ampersands are percent-encoded
        """
        result = encode_url(b"hello world&foo=bar")
        assert " " not in result
        assert "&" not in result

    def test_decode_percent_encoded(self) -> None:
        """
        Checks that %20 decodes to a space
        """
        assert decode_url("hello%20world") == b"hello world"

    def test_roundtrip(self) -> None:
        """
        Encodes then decodes a URL with a query string and checks it matches the original
        """
        original = b"path/to/file?key=value&other=test"
        assert decode_url(encode_url(original)) == original

    def test_form_encode_space_as_plus(self) -> None:
        """
        Checks that form encoding turns spaces into + rather than %20
        """
        result = encode_url(b"hello world", form = True)
        assert "+" in result
        assert "%20" not in result

    def test_form_decode_plus_as_space(self) -> None:
        """
        Checks that form decoding turns + back into a space
        """
        assert decode_url("hello+world", form = True) == b"hello world"


class TestRot13:
    def test_encode_simple(self) -> None:
        """
        Checks that 'Hello' rotates to 'Uryyb'
        """
        assert encode_rot13(b"Hello") == "Uryyb"

    def test_decode_simple(self) -> None:
        """
        Checks that 'Uryyb' rotates back to the bytes 'Hello'
        """
        assert decode_rot13("Uryyb") == b"Hello"

    def test_is_its_own_inverse(self) -> None:
        """
        Checks that applying ROT13 twice returns the original text
        """
        once = encode_rot13(b"Attack at dawn")
        twice = decode_rot13(once)
        assert twice == b"Attack at dawn"

    def test_non_letters_unchanged(self) -> None:
        """
        Checks that digits, spaces, and punctuation pass through untouched
        """
        assert encode_rot13(b"abc 123 XYZ!") == "nop 123 KLM!"

    def test_binary_roundtrip(self) -> None:
        """
        Checks that arbitrary bytes survive a ROT13 roundtrip losslessly
        """
        data = bytes(range(256))
        assert decode_rot13(encode_rot13(data)) == data


class TestAscii85:
    def test_encode_matches_stdlib(self) -> None:
        """
        Checks that ASCII85 encoding matches Python's base64.a85encode
        """
        assert encode_ascii85(b"Hello World") == b64.a85encode(
            b"Hello World"
        ).decode("ascii")

    def test_decode_simple(self) -> None:
        """
        Checks that a known ASCII85 string decodes to 'Hello World'
        """
        assert decode_ascii85('87cURD]i,"Ebo7') == b"Hello World"

    def test_decode_adobe_wrapper(self) -> None:
        """
        Checks that Adobe's <~...~> wrapped ASCII85 decodes correctly
        """
        wrapped = "<~" + encode_ascii85(b"payload") + "~>"
        assert decode_ascii85(wrapped) == b"payload"

    def test_decode_with_whitespace(self) -> None:
        """
        Checks that whitespace inside ASCII85 input is ignored on decode
        """
        encoded = encode_ascii85(b"Hello World")
        spaced = encoded[: 4] + "\n" + encoded[4:]
        assert decode_ascii85(spaced) == b"Hello World"

    def test_binary_roundtrip(self) -> None:
        """
        Checks that all 256 byte values survive an ASCII85 roundtrip
        """
        data = bytes(range(256))
        assert decode_ascii85(encode_ascii85(data)) == data


class TestCustomAlphabet:
    def test_standard_alphabet_matches_stdlib(self) -> None:
        """
        Checks that encoding with the standard alphabet equals base64.b64encode
        """
        result = encode_base64_custom(b"secret", STANDARD_ALPHABET)
        assert result == b64.b64encode(b"secret").decode("ascii")

    def test_reversed_alphabet_roundtrip(self) -> None:
        """
        Checks that a scrambled alphabet round-trips losslessly
        """
        encoded = encode_base64_custom(b"attack payload", REVERSED_ALPHABET)
        assert decode_base64_custom(encoded, REVERSED_ALPHABET) == b"attack payload"

    def test_reversed_alphabet_differs_from_standard(self) -> None:
        """
        Checks that a custom alphabet produces different output than standard base64
        """
        custom = encode_base64_custom(b"secret", REVERSED_ALPHABET)
        standard = encode_base64_custom(b"secret", STANDARD_ALPHABET)
        assert custom != standard

    def test_binary_roundtrip(self) -> None:
        """
        Checks that all 256 byte values survive a custom-alphabet roundtrip
        """
        data = bytes(range(256))
        encoded = encode_base64_custom(data, REVERSED_ALPHABET)
        assert decode_base64_custom(encoded, REVERSED_ALPHABET) == data

    def test_65_char_alphabet_with_custom_padding(self) -> None:
        """
        Checks that a 65-character alphabet uses its final char as padding
        """
        alphabet = REVERSED_ALPHABET + "!"
        # A 2-byte input needs one padding character to fill the final quad.
        encoded = encode_base64_custom(b"hi", alphabet)
        assert encoded.endswith("!")
        assert decode_base64_custom(encoded, alphabet) == b"hi"

    def test_wrong_length_alphabet_raises(self) -> None:
        """
        Checks that an alphabet that is not 64 or 65 characters is rejected
        """
        with pytest.raises(ValueError):
            encode_base64_custom(b"data", "tooshort")

    def test_non_distinct_alphabet_raises(self) -> None:
        """
        Checks that an alphabet with duplicate characters is rejected
        """
        with pytest.raises(ValueError):
            encode_base64_custom(b"data", "A" * 64)

    def test_char_outside_alphabet_raises(self) -> None:
        """
        Checks that decoding a character not in the alphabet raises ValueError
        """
        with pytest.raises(ValueError):
            decode_base64_custom("****", REVERSED_ALPHABET)


class TestRegistryDispatch:
    @pytest.mark.parametrize("fmt", list(EncodingFormat))
    def test_encode_decode_roundtrip(
        self,
        fmt: EncodingFormat,
    ) -> None:
        """
        Checks that all registered formats produce a lossless roundtrip via encode() and decode()
        """
        original = b"roundtrip test data"
        encoded = encode(original, fmt)
        decoded = decode(encoded, fmt)
        assert decoded == original

    def test_try_decode_valid(self) -> None:
        """
        Checks that try_decode returns the correct bytes for valid input
        """
        result = try_decode("SGVsbG8=", EncodingFormat.BASE64)
        assert result == b"Hello"

    def test_try_decode_invalid_returns_none(self) -> None:
        """
        Checks that try_decode returns None instead of raising for garbage input
        """
        result = try_decode("!!!bad!!!", EncodingFormat.BASE64)
        assert result is None