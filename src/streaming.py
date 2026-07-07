"""
streaming.py

Constant-memory streaming encode/decode for large files

Processes data in aligned blocks with generators so that a file of any
size can be encoded or decoded without loading it fully into memory.
Base64/base64url are buffered in multiples of 3 bytes (encode) or 4
characters (decode); hex is processed a byte / two characters at a
time. Whitespace in decoder input is stripped before block alignment.

Key exports:
  stream_encode() - Yields encoded string chunks from a binary reader
  stream_decode() - Yields decoded byte chunks from a binary reader
  stream_transform() - Writes streamed encode/decode output to a writer
  should_stream() - True when a file exceeds the auto-stream size threshold
  STREAMABLE_FORMATS - Formats supporting streaming
  STREAM_CHUNK_SIZE, STREAM_SIZE_THRESHOLD - Block size and auto-stream cutoff

Connects to:
  constants.py - imports EncodingFormat
  cli.py - imports stream_transform, should_stream, STREAMABLE_FORMATS
  test_streaming.py - tests block alignment and roundtrips
"""

import base64 as b64
from collections.abc import Callable, Iterator
from typing import BinaryIO, Final

from base64_tool.constants import EncodingFormat


STREAM_CHUNK_SIZE: Final[int] = 64 * 1024

# Files at or above this size are streamed automatically when no explicit
# --stream flag is given.
STREAM_SIZE_THRESHOLD: Final[int] = 8 * 1024 * 1024

STREAMABLE_FORMATS: Final[frozenset[EncodingFormat]] = frozenset({
    EncodingFormat.BASE64,
    EncodingFormat.BASE64URL,
    EncodingFormat.HEX,
})

_B64_ENCODERS: Final[dict[EncodingFormat, Callable[[bytes], bytes]]] = {
    EncodingFormat.BASE64: b64.b64encode,
    EncodingFormat.BASE64URL: b64.urlsafe_b64encode,
}

_B64_DECODERS: Final[dict[EncodingFormat, Callable[[str], bytes]]] = {
    EncodingFormat.BASE64: b64.b64decode,
    EncodingFormat.BASE64URL: b64.urlsafe_b64decode,
}


def should_stream(size: int) -> bool:
    return size >= STREAM_SIZE_THRESHOLD


def _iter_reads(reader: BinaryIO, block: int) -> Iterator[bytes]:
    while True:
        chunk = reader.read(block)
        if not chunk:
            return
        yield chunk


def stream_encode(
    reader: BinaryIO,
    fmt: EncodingFormat,
    *,
    chunk_size: int = STREAM_CHUNK_SIZE,
) -> Iterator[str]:
    if fmt == EncodingFormat.HEX:
        for chunk in _iter_reads(reader, chunk_size):
            yield chunk.hex()
        return

    encoder = _B64_ENCODERS.get(fmt)
    if encoder is None:
        raise ValueError(f"Streaming is not supported for {fmt.value}")

    block = max(3, (chunk_size // 3) * 3)
    leftover = b""
    for chunk in _iter_reads(reader, block):
        buffer = leftover + chunk
        cut = (len(buffer) // 3) * 3
        if cut:
            yield encoder(buffer[: cut]).decode("ascii")
        leftover = buffer[cut:]

    if leftover:
        yield encoder(leftover).decode("ascii")


def stream_decode(
    reader: BinaryIO,
    fmt: EncodingFormat,
    *,
    chunk_size: int = STREAM_CHUNK_SIZE,
) -> Iterator[bytes]:
    if fmt == EncodingFormat.HEX:
        block = max(2, (chunk_size // 2) * 2)
        leftover = ""
        for chunk in _iter_reads(reader, block):
            buffer = leftover + "".join(chunk.decode("ascii").split())
            cut = (len(buffer) // 2) * 2
            if cut:
                yield bytes.fromhex(buffer[: cut])
            leftover = buffer[cut:]
        if leftover:
            raise ValueError("Hex input has an odd number of characters")
        return

    decoder = _B64_DECODERS.get(fmt)
    if decoder is None:
        raise ValueError(f"Streaming is not supported for {fmt.value}")

    block = max(4, (chunk_size // 4) * 4)
    leftover = ""
    for chunk in _iter_reads(reader, block):
        buffer = leftover + "".join(chunk.decode("ascii").split())
        cut = (len(buffer) // 4) * 4
        if cut:
            yield decoder(buffer[: cut])
        leftover = buffer[cut:]

    if leftover:
        yield decoder(leftover)


def stream_transform(
    reader: BinaryIO,
    writer: BinaryIO,
    fmt: EncodingFormat,
    *,
    decode: bool = False,
    chunk_size: int = STREAM_CHUNK_SIZE,
) -> int:
    """
    Stream data through an encode or decode and write it to `writer`.
    Returns the total number of output bytes written.
    """
    written = 0
    if decode:
        for out_bytes in stream_decode(reader, fmt, chunk_size = chunk_size):
            writer.write(out_bytes)
            written += len(out_bytes)
    else:
        for out_str in stream_encode(reader, fmt, chunk_size = chunk_size):
            encoded = out_str.encode("ascii")
            writer.write(encoded)
            written += len(encoded)
    return written
