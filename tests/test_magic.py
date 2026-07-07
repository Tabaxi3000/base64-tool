"""
test_magic.py

Tests for file-type magic-byte detection in magic.py

Verifies that known signatures (PNG, ZIP, ELF, PE, PDF, GIF) are
identified from their leading bytes, that unknown data returns None,
that only a leading match counts, and that suggested_filename builds
the correct extension.

Tests:
  TestIdentifyFileType - each known signature and the no-match case
  TestSuggestedFilename - extension for known and unknown data

Connects to:
  magic.py - functions under test
"""

import pytest

from base64_tool.magic import identify_file_type, suggested_filename


class TestIdentifyFileType:
    @pytest.mark.parametrize(
        ("data", "name"),
        [
            (b"\x89PNG\r\n\x1a\n\x00\x00", "PNG image"),
            (b"PK\x03\x04rest", "ZIP/DOCX/JAR archive"),
            (b"\x7fELF\x02\x01", "ELF executable"),
            (b"MZ\x90\x00", "PE executable"),
            (b"%PDF-1.7", "PDF document"),
            (b"GIF89a...", "GIF image"),
            (b"GIF87a...", "GIF image"),
            (b"\xff\xd8\xff\xe0", "JPEG image"),
        ],
    )
    def test_known_signatures(self, data: bytes, name: str) -> None:
        """
        Checks that each known magic-byte signature is identified
        """
        result = identify_file_type(data)
        assert result is not None
        assert result.name == name

    def test_unknown_returns_none(self) -> None:
        """
        Checks that plain text with no known signature returns None
        """
        assert identify_file_type(b"just some plain text bytes") is None

    def test_signature_must_be_at_start(self) -> None:
        """
        Checks that a signature appearing mid-stream is not matched
        """
        assert identify_file_type(b"xx%PDF-1.7") is None

    def test_empty_returns_none(self) -> None:
        """
        Checks that empty input returns None
        """
        assert identify_file_type(b"") is None


class TestSuggestedFilename:
    def test_known_extension(self) -> None:
        """
        Checks that a PNG blob suggests a .png filename
        """
        assert suggested_filename("out", b"\x89PNG\r\n\x1a\n") == "out.png"

    def test_unknown_extension_is_bin(self) -> None:
        """
        Checks that unrecognized data falls back to a .bin filename
        """
        assert suggested_filename("out", b"random data") == "out.bin"
