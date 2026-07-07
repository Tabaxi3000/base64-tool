"""
test_streaming.py

Tests for constant-memory streaming encode/decode in streaming.py

Verifies that streamed base64, base64url, and hex output matches the
non-streaming encoders regardless of block alignment, that decoders
tolerate embedded whitespace, that stream_transform writes correct
output, and that unsupported formats and the auto-stream size check
behave as expected.

Tests:
  TestStreamEncode - streamed output matches stdlib for aligned and unaligned sizes
  TestStreamDecode - streamed decode round-trips and ignores whitespace
  TestStreamTransform - writes encoded/decoded bytes to a writer
  TestStreamGuards - unsupported formats raise, should_stream threshold

Connects to:
  streaming.py - functions under test
  constants.py - imports EncodingFormat
"""

import base64 as b64
import io

import pytest

from base64_tool.constants import EncodingFormat
from base64_tool.streaming import (
    STREAM_SIZE_THRESHOLD,
    should_stream,
    stream_decode,
    stream_encode,
    stream_transform,
)


class TestStreamEncode:
    @pytest.mark.parametrize("size", [0, 1, 2, 3, 4, 5, 100, 999])
    def test_base64_matches_stdlib(self, size: int) -> None:
        """
        Checks that streamed base64 equals base64.b64encode for many sizes
        """
        data = bytes(i % 256 for i in range(size))
        streamed = "".join(
            stream_encode(io.BytesIO(data), EncodingFormat.BASE64, chunk_size = 7)
        )
        assert streamed == b64.b64encode(data).decode("ascii")

    def test_base64url_matches_stdlib(self) -> None:
        """
        Checks that streamed base64url equals base64.urlsafe_b64encode
        """
        data = b"\xfb\xff\xfe" * 40
        streamed = "".join(
            stream_encode(
                io.BytesIO(data),
                EncodingFormat.BASE64URL,
                chunk_size = 8,
            )
        )
        assert streamed == b64.urlsafe_b64encode(data).decode("ascii")

    def test_hex_matches_stdlib(self) -> None:
        """
        Checks that streamed hex equals bytes.hex for an unaligned chunk size
        """
        data = bytes(range(200))
        streamed = "".join(
            stream_encode(io.BytesIO(data), EncodingFormat.HEX, chunk_size = 5)
        )
        assert streamed == data.hex()


class TestStreamDecode:
    @pytest.mark.parametrize("size", [0, 1, 2, 3, 4, 63, 300])
    def test_base64_roundtrip(self, size: int) -> None:
        """
        Checks that streamed base64 decode recovers the original bytes
        """
        data = bytes((i * 7) % 256 for i in range(size))
        encoded = b64.b64encode(data)
        decoded = b"".join(
            stream_decode(
                io.BytesIO(encoded),
                EncodingFormat.BASE64,
                chunk_size = 6,
            )
        )
        assert decoded == data

    def test_decode_ignores_whitespace(self) -> None:
        """
        Checks that newlines embedded in base64 input are ignored on decode
        """
        encoded = b64.b64encode(b"streaming across newlines works").decode()
        wrapped = "\n".join(
            encoded[i: i + 4] for i in range(0, len(encoded), 4)
        )
        decoded = b"".join(
            stream_decode(
                io.BytesIO(wrapped.encode("ascii")),
                EncodingFormat.BASE64,
                chunk_size = 5,
            )
        )
        assert decoded == b"streaming across newlines works"

    def test_hex_roundtrip(self) -> None:
        """
        Checks that streamed hex decode recovers the original bytes
        """
        data = bytes(range(256))
        decoded = b"".join(
            stream_decode(
                io.BytesIO(data.hex().encode("ascii")),
                EncodingFormat.HEX,
                chunk_size = 3,
            )
        )
        assert decoded == data

    def test_odd_length_hex_raises(self) -> None:
        """
        Checks that hex input with an odd number of characters raises
        """
        with pytest.raises(ValueError):
            list(
                stream_decode(
                    io.BytesIO(b"abc"),
                    EncodingFormat.HEX,
                    chunk_size = 4,
                )
            )


class TestStreamTransform:
    def test_encode_writes_bytes(self) -> None:
        """
        Checks that stream_transform writes encoded output and returns its length
        """
        data = b"transform me into base64"
        writer = io.BytesIO()
        written = stream_transform(
            io.BytesIO(data),
            writer,
            EncodingFormat.BASE64,
        )
        assert writer.getvalue() == b64.b64encode(data)
        assert written == len(writer.getvalue())

    def test_decode_writes_bytes(self) -> None:
        """
        Checks that stream_transform decode writes the original bytes back
        """
        data = b"transform me back"
        writer = io.BytesIO()
        stream_transform(
            io.BytesIO(b64.b64encode(data)),
            writer,
            EncodingFormat.BASE64,
            decode = True,
        )
        assert writer.getvalue() == data


class TestStreamGuards:
    def test_unsupported_encode_format_raises(self) -> None:
        """
        Checks that streaming an unsupported format raises ValueError
        """
        with pytest.raises(ValueError):
            list(
                stream_encode(io.BytesIO(b"data"), EncodingFormat.BASE32)
            )

    def test_should_stream_threshold(self) -> None:
        """
        Checks that should_stream honors the size threshold boundary
        """
        assert should_stream(STREAM_SIZE_THRESHOLD) is True
        assert should_stream(STREAM_SIZE_THRESHOLD - 1) is False
