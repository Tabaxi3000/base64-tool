"""
test_recipe.py

Tests for CyberChef recipe parsing, execution, and export in recipe.py

Verifies that recipe JSON maps onto b64tool formats, that recipes run
in order, that unsupported operations and malformed JSON are rejected,
and that a peel result exports to a decode recipe that reproduces the
same layer stripping.

Tests:
  TestParseRecipe - operation mapping, wrapper object, error cases
  TestExecuteRecipe - encode chain, decode reverse, roundtrip
  TestExportRecipe - peel_to_recipe and recipe_to_json round-trip

Connects to:
  recipe.py - functions under test
  constants.py - imports EncodingFormat
  encoders.py - imports encode
  peeler.py - imports peel
"""

import json

import pytest

from base64_tool.constants import EncodingFormat
from base64_tool.encoders import encode
from base64_tool.peeler import peel
from base64_tool.recipe import (
    execute_recipe,
    parse_recipe,
    peel_to_recipe,
    recipe_to_json,
)


class TestParseRecipe:
    def test_maps_operations(self) -> None:
        """
        Checks that To Base64 and To Hex map to the right formats and directions
        """
        ops = parse_recipe('[{"op": "To Base64"}, {"op": "From Hex"}]')
        assert ops[0].fmt == EncodingFormat.BASE64
        assert ops[0].decode is False
        assert ops[1].fmt == EncodingFormat.HEX
        assert ops[1].decode is True

    def test_operation_names_case_insensitive(self) -> None:
        """
        Checks that operation names are matched case-insensitively
        """
        ops = parse_recipe('[{"op": "from base64"}]')
        assert ops[0].fmt == EncodingFormat.BASE64
        assert ops[0].decode is True

    def test_accepts_recipe_wrapper_object(self) -> None:
        """
        Checks that a {"recipe": [...]} wrapper object is unwrapped
        """
        ops = parse_recipe('{"recipe": [{"op": "To Hex"}]}')
        assert ops[0].fmt == EncodingFormat.HEX

    def test_unknown_operation_raises(self) -> None:
        """
        Checks that an unsupported CyberChef operation raises ValueError
        """
        with pytest.raises(ValueError):
            parse_recipe('[{"op": "AES Decrypt"}]')

    def test_invalid_json_raises(self) -> None:
        """
        Checks that malformed recipe JSON raises ValueError
        """
        with pytest.raises(ValueError):
            parse_recipe("{not valid json")

    def test_empty_recipe_raises(self) -> None:
        """
        Checks that a recipe with no operations raises ValueError
        """
        with pytest.raises(ValueError):
            parse_recipe("[]")


class TestExecuteRecipe:
    def test_encode_chain(self) -> None:
        """
        Checks that a To Base64 then To Hex recipe produces the expected bytes
        """
        ops = parse_recipe('[{"op": "To Base64"}, {"op": "To Hex"}]')
        _, final = execute_recipe(ops, b"Hi")
        # "Hi" -> base64 "SGk=" -> hex of "SGk="
        assert final == b"SGk=".hex().encode("ascii")

    def test_decode_reverse_roundtrip(self) -> None:
        """
        Checks that From Hex then From Base64 undoes To Base64 then To Hex
        """
        encode_ops = parse_recipe('[{"op": "To Base64"}, {"op": "To Hex"}]')
        _, encoded = execute_recipe(encode_ops, b"secret message")

        decode_ops = parse_recipe('[{"op": "From Hex"}, {"op": "From Base64"}]')
        _, decoded = execute_recipe(decode_ops, encoded)
        assert decoded == b"secret message"

    def test_steps_recorded(self) -> None:
        """
        Checks that one RecipeStep is recorded per operation
        """
        ops = parse_recipe('[{"op": "To Base64"}, {"op": "To Hex"}]')
        steps, _ = execute_recipe(ops, b"data")
        assert len(steps) == 2
        assert steps[0].operation.op_name == "To Base64"


class TestExportRecipe:
    def test_peel_to_recipe_matches_layers(self) -> None:
        """
        Checks that exporting a peel produces one decode op per peeled layer
        """
        step1 = encode(b"payload", EncodingFormat.BASE64)
        step2 = encode(step1.encode("utf-8"), EncodingFormat.HEX)
        result = peel(step2)

        ops = peel_to_recipe(result)
        assert len(ops) == len(result.layers)
        assert all(op.decode for op in ops)
        assert ops[0].fmt == result.layers[0].format

    def test_recipe_to_json_is_valid_and_reimportable(self) -> None:
        """
        Checks that exported recipe JSON parses back into the same operations
        """
        step1 = encode(b"payload", EncodingFormat.BASE64)
        step2 = encode(step1.encode("utf-8"), EncodingFormat.HEX)
        result = peel(step2)

        recipe_json = recipe_to_json(peel_to_recipe(result))
        parsed = json.loads(recipe_json)
        assert isinstance(parsed, list)
        assert parsed[0]["op"] == "From Hex"

        reimported = parse_recipe(recipe_json)
        assert [op.fmt for op in reimported] == [
            layer.format for layer in result.layers
        ]
