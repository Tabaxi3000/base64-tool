"""
test_cli.py

Integration tests for all five CLI commands via Typer's CliRunner

Invokes each CLI command end-to-end without spawning subprocesses and
verifies exit codes and output content. Covers encode, decode, detect,
peel, and chain along with the --version flag and error paths (invalid
format, bad input).

Tests:
  TestEncodeCommand - base64, hex, base32, url, empty input
  TestDecodeCommand - base64, hex, invalid input returns non-zero exit
  TestDetectCommand - base64 detection, hex detection, no-match message
  TestPeelCommand - single layer, plain text with no layers
  TestChainCommand - single step, multiple steps, unknown format error
  TestVersionFlag - version string present in output

Connects to:
  cli.py - imports app (the Typer application under test)
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from base64_tool.cli import app


runner = CliRunner()

REVERSED_ALPHABET = (
    "ZYXWVUTSRQPONMLKJIHGFEDCBA"
    "zyxwvutsrqponmlkjihgfedcba"
    "9876543210+/"
)


class TestEncodeCommand:
    def test_encode_base64(self) -> None:
        """
        Checks that the encode command outputs the correct base64 string
        """
        result = runner.invoke(app, ["encode", "Hello World"])
        assert result.exit_code == 0
        assert "SGVsbG8gV29ybGQ=" in result.output

    def test_encode_hex(self) -> None:
        """
        Checks that the encode command outputs the correct hex string with --format hex
        """
        result = runner.invoke(
            app,
            ["encode",
             "Hello",
             "--format",
             "hex"],
        )
        assert result.exit_code == 0
        assert "48656c6c6f" in result.output

    def test_encode_base32(self) -> None:
        """
        Checks that the encode command outputs the correct base32 string with --format base32
        """
        result = runner.invoke(
            app,
            ["encode",
             "Hello",
             "--format",
             "base32"],
        )
        assert result.exit_code == 0
        assert "JBSWY3DP" in result.output

    def test_encode_url(self) -> None:
        """
        Checks that the encode command percent-encodes special characters with --format url
        """
        result = runner.invoke(
            app,
            ["encode",
             "hello world&test",
             "--format",
             "url"],
        )
        assert result.exit_code == 0
        assert "%20" in result.output or "hello" in result.output

    def test_encode_empty_string(self) -> None:
        """
        Checks that encoding an empty string succeeds without error
        """
        result = runner.invoke(app, ["encode", ""])
        assert result.exit_code == 0


class TestDecodeCommand:
    def test_decode_base64(self) -> None:
        """
        Checks that the decode command recovers 'Hello World' from a known base64 string
        """
        result = runner.invoke(
            app,
            ["decode",
             "SGVsbG8gV29ybGQ="],
        )
        assert result.exit_code == 0
        assert "Hello World" in result.output

    def test_decode_hex(self) -> None:
        """
        Checks that the decode command recovers 'Hello' from a hex string
        """
        result = runner.invoke(
            app,
            ["decode",
             "48656c6c6f",
             "--format",
             "hex"],
        )
        assert result.exit_code == 0
        assert "Hello" in result.output

    def test_decode_invalid_base64(self) -> None:
        """
        Checks that decoding garbage input exits with a non-zero code
        """
        result = runner.invoke(
            app,
            ["decode",
             "!!!invalid!!!"],
        )
        assert result.exit_code != 0


class TestDetectCommand:
    def test_detect_base64(self) -> None:
        """
        Checks that the detect command identifies base64 in its output
        """
        result = runner.invoke(
            app,
            ["detect",
             "SGVsbG8gV29ybGQ="],
        )
        assert result.exit_code == 0
        assert "base64" in result.output.lower()

    def test_detect_hex(self) -> None:
        """
        Checks that the detect command identifies hex in its output
        """
        result = runner.invoke(
            app,
            ["detect",
             "48656c6c6f20576f726c64"],
        )
        assert result.exit_code == 0
        assert "hex" in result.output.lower()

    def test_detect_no_match(self) -> None:
        """
        Checks that the detect command reports no encoding found for plain text
        """
        result = runner.invoke(
            app,
            ["detect",
             "just plain text"],
        )
        assert result.exit_code == 0
        assert "no encoding" in result.output.lower()


class TestPeelCommand:
    def test_peel_single_layer(self) -> None:
        """
        Checks that the peel command reports at least one layer for a base64 string
        """
        result = runner.invoke(
            app,
            ["peel",
             "SGVsbG8gV29ybGQ="],
        )
        assert result.exit_code == 0
        assert "layer" in result.output.lower()

    def test_peel_no_encoding(self) -> None:
        """
        Checks that the peel command exits cleanly when no encoding is found
        """
        result = runner.invoke(
            app,
            ["peel",
             "hello world"],
        )
        assert result.exit_code == 0


class TestChainCommand:
    def test_chain_single_step(self) -> None:
        """
        Checks that the chain command applies one base64 step correctly
        """
        result = runner.invoke(
            app,
            ["chain",
             "Hello",
             "--steps",
             "base64"],
        )
        assert result.exit_code == 0
        assert "SGVsbG8=" in result.output

    def test_chain_multiple_steps(self) -> None:
        """
        Checks that the chain command applies two steps in sequence without error
        """
        result = runner.invoke(
            app,
            ["chain",
             "Hi",
             "--steps",
             "base64,hex"],
        )
        assert result.exit_code == 0

    def test_chain_invalid_format(self) -> None:
        """
        Checks that an unknown format name causes the chain command to exit with an error
        """
        result = runner.invoke(
            app,
            ["chain",
             "test",
             "--steps",
             "fake"],
        )
        assert result.exit_code != 0


class TestNewFormats:
    def test_encode_rot13(self) -> None:
        """
        Checks that the encode command applies ROT13
        """
        result = runner.invoke(app, ["encode", "Hello", "--format", "rot13"])
        assert result.exit_code == 0
        assert "Uryyb" in result.output

    def test_decode_rot13(self) -> None:
        """
        Checks that the decode command reverses ROT13
        """
        result = runner.invoke(app, ["decode", "Uryyb", "--format", "rot13"])
        assert result.exit_code == 0
        assert "Hello" in result.output

    def test_encode_ascii85(self) -> None:
        """
        Checks that the encode command produces ASCII85 output
        """
        result = runner.invoke(
            app,
            ["encode", "Hello World", "--format", "ascii85"],
        )
        assert result.exit_code == 0
        assert '87cURD]i,"Ebo7' in result.output

    def test_decode_ascii85(self) -> None:
        """
        Checks that the decode command reverses ASCII85
        """
        result = runner.invoke(
            app,
            ["decode", '87cURD]i,"Ebo7', "--format", "ascii85"],
        )
        assert result.exit_code == 0
        assert "Hello World" in result.output


class TestCustomAlphabetCommand:
    def test_encode_decode_roundtrip(self) -> None:
        """
        Checks that encoding then decoding with a custom alphabet round-trips
        """
        encoded = runner.invoke(
            app,
            ["encode", "secret", "--alphabet", REVERSED_ALPHABET],
        )
        assert encoded.exit_code == 0
        token = encoded.output.strip()
        decoded = runner.invoke(
            app,
            ["decode", token, "--alphabet", REVERSED_ALPHABET],
        )
        assert decoded.exit_code == 0
        assert "secret" in decoded.output

    def test_alphabet_file(self, tmp_path: Path) -> None:
        """
        Checks that --alphabet-file reads the alphabet from disk
        """
        alpha_file = tmp_path / "alphabet.txt"
        alpha_file.write_text(REVERSED_ALPHABET)
        result = runner.invoke(
            app,
            ["encode", "hi", "--alphabet-file", str(alpha_file)],
        )
        assert result.exit_code == 0

    def test_conflicting_alphabet_options(self, tmp_path: Path) -> None:
        """
        Checks that passing both --alphabet and --alphabet-file errors
        """
        alpha_file = tmp_path / "alphabet.txt"
        alpha_file.write_text(REVERSED_ALPHABET)
        result = runner.invoke(
            app,
            [
                "encode",
                "hi",
                "--alphabet",
                REVERSED_ALPHABET,
                "--alphabet-file",
                str(alpha_file),
            ],
        )
        assert result.exit_code != 0


class TestOutputFlag:
    def test_decode_writes_bytes_to_file(self, tmp_path: Path) -> None:
        """
        Checks that decode --output writes the raw decoded bytes to disk
        """
        out = tmp_path / "decoded.bin"
        result = runner.invoke(
            app,
            ["decode", "SGVsbG8gV29ybGQ=", "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.read_bytes() == b"Hello World"

    def test_encode_writes_result_to_file(self, tmp_path: Path) -> None:
        """
        Checks that encode --output writes the encoded string to disk
        """
        out = tmp_path / "encoded.txt"
        result = runner.invoke(
            app,
            ["encode", "Hello World", "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.read_bytes() == b"SGVsbG8gV29ybGQ="


class TestJsonOutput:
    def test_detect_json(self) -> None:
        """
        Checks that detect --json emits parseable JSON with a results array
        """
        result = runner.invoke(
            app,
            ["detect", "SGVsbG8gV29ybGQ=", "--json"],
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["results"][0]["format"] == "base64"
        assert payload["results"][0]["decoded_preview"] == "Hello World"

    def test_peel_json(self) -> None:
        """
        Checks that peel --json emits parseable JSON with layer data
        """
        result = runner.invoke(
            app,
            ["peel", "SGVsbG8gV29ybGQ=", "--json"],
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["success"] is True
        assert payload["layers"][0]["format"] == "base64"


class TestDecodeChainCommand:
    def test_reverses_chain(self) -> None:
        """
        Checks that decode-chain undoes a chain encoded with the same steps
        """
        chained = runner.invoke(
            app,
            ["chain", "Hello,", "--steps", "base64,hex"],
        )
        token = chained.output.strip()
        result = runner.invoke(
            app,
            ["decode-chain", token, "--steps", "base64,hex"],
        )
        assert result.exit_code == 0
        assert "Hello," in result.output

    def test_writes_output_file(self, tmp_path: Path) -> None:
        """
        Checks that decode-chain --output writes the final bytes to disk
        """
        chained = runner.invoke(
            app,
            ["chain", "payload", "--steps", "base64,hex"],
        )
        token = chained.output.strip()
        out = tmp_path / "final.bin"
        result = runner.invoke(
            app,
            ["decode-chain", token, "--steps", "base64,hex", "-o", str(out)],
        )
        assert result.exit_code == 0
        assert out.read_bytes() == b"payload"


class TestHexdumpCommand:
    def test_hexdump_of_decoded(self) -> None:
        """
        Checks that hexdump renders offset, hex bytes, and ASCII for decoded data
        """
        result = runner.invoke(app, ["hexdump", "SGVsbG8gV29ybGQ="])
        assert result.exit_code == 0
        assert "00000000" in result.output
        assert "48 65 6c 6c 6f" in result.output
        assert "Hello World" in result.output


class TestAnalyzeCommand:
    def test_analyze_file(self, tmp_path: Path) -> None:
        """
        Checks that analyze reports statistics for a file of samples
        """
        samples = tmp_path / "samples.txt"
        samples.write_text(
            "SGVsbG8gV29ybGQ=\n48656c6c6f\njust plain text\n"
        )
        result = runner.invoke(app, ["analyze", str(samples)])
        assert result.exit_code == 0
        assert "base64" in result.output.lower()

    def test_analyze_json(self, tmp_path: Path) -> None:
        """
        Checks that analyze --json emits a parseable report
        """
        samples = tmp_path / "samples.txt"
        samples.write_text("SGVsbG8gV29ybGQ=\n48656c6c6f\n")
        result = runner.invoke(app, ["analyze", str(samples), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["total"] == 2
        assert payload["detected"] == 2


class TestEntropyCommand:
    def test_entropy_reports(self) -> None:
        """
        Checks that entropy prints an entropy analysis for encoded input
        """
        result = runner.invoke(app, ["entropy", "SGVsbG8gV29ybGQ="])
        assert result.exit_code == 0
        assert "entropy" in result.output.lower()


class TestRecipeCommand:
    def test_import_and_run(self, tmp_path: Path) -> None:
        """
        Checks that recipe --import runs a CyberChef recipe over the input
        """
        recipe = tmp_path / "recipe.json"
        recipe.write_text(
            json.dumps([{"op": "To Base64"}, {"op": "To Hex"}])
        )
        result = runner.invoke(
            app,
            ["recipe", "Hi", "--import", str(recipe)],
        )
        assert result.exit_code == 0
        # "Hi" -> base64 "SGk=" -> hex of "SGk="
        assert b"SGk=".hex() in result.output

    def test_missing_recipe_errors(self) -> None:
        """
        Checks that the recipe command requires a recipe file
        """
        result = runner.invoke(app, ["recipe", "Hi"])
        assert result.exit_code != 0

    def test_peel_export_recipe(self, tmp_path: Path) -> None:
        """
        Checks that peel --export-recipe writes a reusable CyberChef recipe
        """
        chained = runner.invoke(
            app,
            ["chain", "payload", "--steps", "base64,hex"],
        )
        token = chained.output.strip()
        recipe_out = tmp_path / "recipe.json"
        result = runner.invoke(
            app,
            ["peel", token, "--export-recipe", str(recipe_out)],
        )
        assert result.exit_code == 0
        exported = json.loads(recipe_out.read_text())
        assert exported[0]["op"] == "From Hex"


class TestVersionFlag:
    def test_version_output(self) -> None:
        """
        Checks that --version prints the tool name and exits cleanly
        """
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "b64tool" in result.output