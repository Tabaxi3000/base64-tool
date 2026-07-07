"""
magic.py

File-type detection from magic bytes in decoded output

Compares the leading bytes of decoded data against a table of known
file signatures (PNG, ZIP, ELF, PE, PDF, GIF, and more). Used after
decode and peel to tell an analyst whether a blob is an image, an
archive, or an executable rather than plain text.

Key exports:
  FileType - Frozen dataclass with the detected name and file extension
  identify_file_type() - Returns the matching FileType for bytes, or None
  suggested_filename() - Builds a filename with the detected extension

Connects to:
  constants.py - imports MAGIC_SIGNATURES
  formatter.py - imports identify_file_type for display
  cli.py - imports identify_file_type, suggested_filename
  test_magic.py - tests signature matching
"""

from dataclasses import dataclass

from base64_tool.constants import MAGIC_SIGNATURES


@dataclass(frozen = True, slots = True)
class FileType:
    name: str
    extension: str


def identify_file_type(data: bytes) -> FileType | None:
    for signature, name, extension in MAGIC_SIGNATURES:
        if data.startswith(signature):
            return FileType(name = name, extension = extension)
    return None


def suggested_filename(stem: str, data: bytes) -> str:
    file_type = identify_file_type(data)
    if file_type is None:
        return f"{stem}.bin"
    return f"{stem}.{file_type.extension}"
