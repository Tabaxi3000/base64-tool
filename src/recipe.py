"""
recipe.py

CyberChef recipe import/export and execution

Parses CyberChef "recipe" JSON (a list of {op, args} operations), maps
each operation onto a b64tool EncodingFormat and direction, and runs
the recipe as an ordered chain. Also exports a peel result as a
CyberChef recipe of decode operations so an analyst can reproduce the
same layer-stripping in CyberChef.

Key exports:
  RecipeOperation - Frozen dataclass: format, CyberChef op name, decode flag
  RecipeStep - One executed step: the operation and its output preview
  parse_recipe() - Parses recipe JSON into RecipeOperation list
  execute_recipe() - Runs operations in order over input bytes
  peel_to_recipe() - Builds a decode recipe from a PeelResult
  recipe_to_json() - Serializes RecipeOperations to CyberChef recipe JSON

Connects to:
  constants.py - imports EncodingFormat
  encoders.py - imports encode, decode
  peeler.py - imports PeelResult
  cli.py - imports parse_recipe, execute_recipe, peel_to_recipe, recipe_to_json
  test_recipe.py - tests parsing, execution, and export roundtrips
"""

import json
from dataclasses import dataclass
from typing import Any

from base64_tool.constants import EncodingFormat
from base64_tool.encoders import decode, encode
from base64_tool.peeler import PeelResult


@dataclass(frozen = True, slots = True)
class RecipeOperation:
    fmt: EncodingFormat
    op_name: str
    decode: bool


@dataclass(frozen = True, slots = True)
class RecipeStep:
    operation: RecipeOperation
    output_preview: str


# CyberChef operation name (lowercased) -> (format, is_decode). ROT13 is its
# own inverse, so it is always treated as an encode-direction operation.
_OP_TO_FORMAT: dict[str, tuple[EncodingFormat, bool]] = {
    "to base64": (EncodingFormat.BASE64, False),
    "from base64": (EncodingFormat.BASE64, True),
    "to base32": (EncodingFormat.BASE32, False),
    "from base32": (EncodingFormat.BASE32, True),
    "to hex": (EncodingFormat.HEX, False),
    "from hex": (EncodingFormat.HEX, True),
    "to base85": (EncodingFormat.ASCII85, False),
    "from base85": (EncodingFormat.ASCII85, True),
    "to ascii85": (EncodingFormat.ASCII85, False),
    "from ascii85": (EncodingFormat.ASCII85, True),
    "url encode": (EncodingFormat.URL, False),
    "url decode": (EncodingFormat.URL, True),
    "rot13": (EncodingFormat.ROT13, False),
}

# Canonical CyberChef operation name for a (format, is_decode) pair.
_FORMAT_TO_OP: dict[tuple[EncodingFormat, bool], str] = {
    (EncodingFormat.BASE64, False): "To Base64",
    (EncodingFormat.BASE64, True): "From Base64",
    (EncodingFormat.BASE32, False): "To Base32",
    (EncodingFormat.BASE32, True): "From Base32",
    (EncodingFormat.HEX, False): "To Hex",
    (EncodingFormat.HEX, True): "From Hex",
    (EncodingFormat.ASCII85, False): "To Base85",
    (EncodingFormat.ASCII85, True): "From Base85",
    (EncodingFormat.URL, False): "URL Encode",
    (EncodingFormat.URL, True): "URL Decode",
    (EncodingFormat.ROT13, False): "ROT13",
    (EncodingFormat.ROT13, True): "ROT13",
    (EncodingFormat.BASE64URL, False): "To Base64",
    (EncodingFormat.BASE64URL, True): "From Base64",
}

# Default CyberChef arguments emitted on export, chosen to match this tool's
# own encoder output so the exported recipe round-trips.
_DEFAULT_ARGS: dict[str, list[Any]] = {
    "To Base64": ["A-Za-z0-9+/="],
    "From Base64": ["A-Za-z0-9+/=", True],
    "To Base32": ["A-Z2-7="],
    "From Base32": ["A-Z2-7="],
    "To Hex": ["None"],
    "From Hex": ["Auto"],
    "To Base85": ["!-u"],
    "From Base85": ["!-u"],
    "URL Encode": [True],
    "URL Decode": [],
    "ROT13": [True, True, 13],
}


def parse_recipe(json_text: str) -> list[RecipeOperation]:
    try:
        raw = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid recipe JSON: {exc}") from None

    if isinstance(raw, dict) and "recipe" in raw:
        raw = raw["recipe"]
    if not isinstance(raw, list):
        raise ValueError("Recipe must be a JSON list of operations")

    operations: list[RecipeOperation] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("Each recipe operation must be a JSON object")
        name = entry.get("op") or entry.get("operation")
        if not isinstance(name, str):
            raise ValueError("Recipe operation is missing an 'op' name")
        key = name.strip().lower()
        if key not in _OP_TO_FORMAT:
            raise ValueError(f"Unsupported CyberChef operation: {name!r}")
        fmt, is_decode = _OP_TO_FORMAT[key]
        operations.append(
            RecipeOperation(fmt = fmt, op_name = name, decode = is_decode)
        )

    if not operations:
        raise ValueError("Recipe contains no operations")

    return operations


def execute_recipe(
    operations: list[RecipeOperation],
    data: bytes,
) -> tuple[list[RecipeStep], bytes]:
    steps: list[RecipeStep] = []
    current = data

    for operation in operations:
        if operation.decode:
            result = decode(current.decode("utf-8"), operation.fmt)
            current = result
            preview = _preview_bytes(result)
        else:
            encoded = encode(current, operation.fmt)
            current = encoded.encode("utf-8")
            preview = encoded
        steps.append(
            RecipeStep(operation = operation, output_preview = preview)
        )

    return steps, current


def peel_to_recipe(result: PeelResult) -> list[RecipeOperation]:
    return [
        RecipeOperation(
            fmt = layer.format,
            op_name = _FORMAT_TO_OP[(layer.format, True)],
            decode = True,
        )
        for layer in result.layers
    ]


def recipe_to_json(operations: list[RecipeOperation]) -> str:
    recipe = [
        {
            "op": operation.op_name,
            "args": _DEFAULT_ARGS.get(operation.op_name, []),
        }
        for operation in operations
    ]
    return json.dumps(recipe, indent = 2)


def _preview_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex()
