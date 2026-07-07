"""
cli.py

Typer CLI application with encoding, detection, and analysis commands

Defines the b64tool Typer app and its commands: encode, decode, detect,
peel, chain, decode-chain, hexdump, analyze, entropy, and recipe. Each
command resolves input from a positional argument, --file, or stdin,
delegates to the appropriate logic module, then passes results to
formatter.py for display. encode/decode support custom base64 alphabets
(--alphabet), constant-memory streaming (--stream), and writing raw
output to a file (--output). detect and peel support JSON output (--json).

Key exports:
  app - The Typer application instance registered as the CLI entry point

Connects to:
  __init__.py - imports __version__
  constants.py - imports EncodingFormat, ExitCode, PEEL_MAX_DEPTH
  encoders.py - imports encode, decode, custom-alphabet and URL helpers
  detector.py - imports detect_encoding, score_all_formats
  peeler.py - imports peel
  streaming.py - imports stream_transform, should_stream, STREAMABLE_FORMATS
  analyze.py - imports analyze_samples, report_to_dict
  entropy.py - imports analyze_entropy
  recipe.py - imports parse_recipe, execute_recipe, peel_to_recipe, recipe_to_json
  formatter.py - imports all print_* and *_to_json functions
  utils.py - imports resolve_input_bytes, resolve_input_text
  test_cli.py - exercises all commands via Typer's CliRunner
"""

import json
import sys
from pathlib import Path
from typing import Annotated, BinaryIO

import typer
from rich.console import Console

from base64_tool import __version__
from base64_tool.analyze import analyze_samples, report_to_dict
from base64_tool.constants import (
    EncodingFormat,
    ExitCode,
    PEEL_MAX_DEPTH,
)
from base64_tool.detector import detect_best, detect_encoding, score_all_formats
from base64_tool.encoders import (
    decode,
    decode_base64_custom,
    decode_url,
    encode,
    encode_base64_custom,
    encode_url,
)
from base64_tool.entropy import analyze_entropy
from base64_tool.formatter import (
    detection_to_json,
    peel_result_to_json,
    print_analysis,
    print_chain_result,
    print_decode_chain_result,
    print_decoded,
    print_detection,
    print_encoded,
    print_entropy,
    print_hexdump,
    print_json,
    print_peel_result,
    print_recipe_result,
)
from base64_tool.peeler import peel
from base64_tool.recipe import (
    execute_recipe,
    parse_recipe,
    peel_to_recipe,
    recipe_to_json,
)
from base64_tool.streaming import (
    STREAMABLE_FORMATS,
    should_stream,
    stream_transform,
)
from base64_tool.utils import (
    resolve_input_bytes,
    resolve_input_text,
)


app = typer.Typer(
    name = "b64tool",
    help = ("Multi-format encoding/decoding CLI "
            "with recursive layer detection"),
    no_args_is_help = True,
    pretty_exceptions_show_locals = False,
)

_console = Console(stderr = True)


def _version_callback(value: bool) -> None:
    if value:
        _console.print(f"b64tool v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            help = "Show version and exit.",
            callback = _version_callback,
            is_eager = True,
        ),
    ] = False,
) -> None:
    pass


def _resolve_alphabet(
    alphabet: str | None,
    alphabet_file: Path | None,
) -> str | None:
    if alphabet is not None and alphabet_file is not None:
        raise typer.BadParameter(
            "Pass either --alphabet or --alphabet-file, not both."
        )
    if alphabet_file is not None:
        if not alphabet_file.exists():
            raise typer.BadParameter(f"File not found: {alphabet_file}")
        return alphabet_file.read_text("utf-8").strip("\n")
    return alphabet


def _write_output(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    _console.print(f"[green]Wrote[/green] {len(data)} bytes to {path}")


def _use_streaming(
    stream: bool,
    file: Path | None,
    fmt: EncodingFormat,
    custom: str | None,
) -> bool:
    if custom is not None:
        return False
    if stream:
        return True
    if file is not None and file.exists():
        if fmt in STREAMABLE_FORMATS and should_stream(file.stat().st_size):
            return True
    return False


def _run_stream(
    file: Path | None,
    output: Path | None,
    fmt: EncodingFormat,
    *,
    decode_mode: bool,
) -> None:
    if fmt not in STREAMABLE_FORMATS:
        valid = ", ".join(sorted(f.value for f in STREAMABLE_FORMATS))
        raise typer.BadParameter(
            f"Streaming supports only: {valid}"
        )

    reader: BinaryIO
    if file is not None:
        if not file.exists():
            raise typer.BadParameter(f"File not found: {file}")
        reader = file.open("rb")
    else:
        reader = sys.stdin.buffer

    writer: BinaryIO
    if output is not None:
        writer = output.open("wb")
    else:
        writer = sys.stdout.buffer

    try:
        written = stream_transform(reader, writer, fmt, decode = decode_mode)
        writer.flush()
    finally:
        if file is not None:
            reader.close()
        if output is not None:
            writer.close()

    if output is not None:
        _console.print(f"[green]Wrote[/green] {written} bytes to {output}")


@app.command(name = "encode")
def encode_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Data to encode."),
    ] = None,
    fmt: Annotated[
        EncodingFormat,
        typer.Option(
            "--format",
            "-f",
            help = "Target encoding format.",
        ),
    ] = EncodingFormat.BASE64,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help = "Write raw result to file instead of stdout.",
        ),
    ] = None,
    form: Annotated[
        bool,
        typer.Option(
            "--form",
            help = "Use form-encoding for URL (space becomes +).",
        ),
    ] = False,
    alphabet: Annotated[
        str | None,
        typer.Option(
            "--alphabet",
            help = "Custom base64 alphabet (64 chars, or 65 with padding).",
        ),
    ] = None,
    alphabet_file: Annotated[
        Path | None,
        typer.Option(
            "--alphabet-file",
            help = "Read the custom base64 alphabet from a file.",
        ),
    ] = None,
    stream: Annotated[
        bool,
        typer.Option(
            "--stream",
            help = "Stream through the file with constant memory.",
        ),
    ] = False,
) -> None:
    try:
        custom = _resolve_alphabet(alphabet, alphabet_file)
        if _use_streaming(stream, file, fmt, custom):
            _run_stream(file, output, fmt, decode_mode = False)
            return

        raw = resolve_input_bytes(data, file)
        if custom is not None:
            result = encode_base64_custom(raw, custom)
        elif fmt == EncodingFormat.URL and form:
            result = encode_url(raw, form = True)
        else:
            result = encode(raw, fmt)

        if output is not None:
            _write_output(output, result.encode("utf-8"))
        else:
            print_encoded(result, fmt)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "decode")
def decode_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Data to decode."),
    ] = None,
    fmt: Annotated[
        EncodingFormat,
        typer.Option(
            "--format",
            "-f",
            help = "Source encoding format.",
        ),
    ] = EncodingFormat.BASE64,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help = "Write raw decoded bytes to file instead of stdout.",
        ),
    ] = None,
    form: Annotated[
        bool,
        typer.Option(
            "--form",
            help = "Use form-decoding for URL (+ becomes space).",
        ),
    ] = False,
    alphabet: Annotated[
        str | None,
        typer.Option(
            "--alphabet",
            help = "Custom base64 alphabet (64 chars, or 65 with padding).",
        ),
    ] = None,
    alphabet_file: Annotated[
        Path | None,
        typer.Option(
            "--alphabet-file",
            help = "Read the custom base64 alphabet from a file.",
        ),
    ] = None,
    stream: Annotated[
        bool,
        typer.Option(
            "--stream",
            help = "Stream through the file with constant memory.",
        ),
    ] = False,
) -> None:
    try:
        custom = _resolve_alphabet(alphabet, alphabet_file)
        if _use_streaming(stream, file, fmt, custom):
            _run_stream(file, output, fmt, decode_mode = True)
            return

        text = resolve_input_text(data, file)
        if custom is not None:
            result = decode_base64_custom(text, custom)
        elif fmt == EncodingFormat.URL and form:
            result = decode_url(text, form = True)
        else:
            result = decode(text, fmt)

        if output is not None:
            _write_output(output, result)
        else:
            print_decoded(result)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "detect")
def detect_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Data to analyze."),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-V",
            help = "Show per-format score breakdown.",
        ),
    ] = False,
    json_out: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Emit structured JSON to stdout.",
        ),
    ] = False,
) -> None:
    try:
        text = resolve_input_text(data, file)
        results = detect_encoding(text)
        if json_out:
            print_json(detection_to_json(results))
            return
        scores = score_all_formats(text) if verbose else None
        print_detection(results, verbose_scores = scores)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "peel")
def peel_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Data to recursively decode."),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
    max_depth: Annotated[
        int,
        typer.Option(
            "--max-depth",
            "-d",
            help = "Maximum decoding layers.",
        ),
    ] = PEEL_MAX_DEPTH,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-V",
            help = "Show per-format score breakdown at each layer.",
        ),
    ] = False,
    json_out: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Emit structured JSON to stdout.",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help = "Write the final decoded output to file.",
        ),
    ] = None,
    export_recipe: Annotated[
        Path | None,
        typer.Option(
            "--export-recipe",
            help = "Export the peel as a CyberChef recipe JSON file.",
        ),
    ] = None,
) -> None:
    try:
        text = resolve_input_text(data, file)
        result = peel(text, max_depth = max_depth, verbose = verbose)

        if export_recipe is not None:
            recipe_json = recipe_to_json(peel_to_recipe(result))
            export_recipe.write_text(recipe_json, encoding = "utf-8")
            _console.print(
                f"[green]Exported recipe to[/green] {export_recipe}"
            )

        if output is not None:
            _write_output(output, result.final_output)

        if json_out:
            print_json(peel_result_to_json(result))
            return
        if output is None:
            print_peel_result(result, verbose = verbose)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "chain")
def chain_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Data to encode through chain."),
    ] = None,
    steps: Annotated[
        str,
        typer.Option(
            "--steps",
            "-s",
            help = ("Comma-separated encoding formats "
                    "(e.g. base64,hex,url)."),
        ),
    ] = "base64",
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
) -> None:
    try:
        raw = resolve_input_bytes(data, file)
        formats = _parse_chain_steps(steps)
        intermediates: list[tuple[EncodingFormat, str]] = []
        current = raw

        for step_fmt in formats:
            encoded = encode(current, step_fmt)
            intermediates.append((step_fmt, encoded))
            current = encoded.encode("utf-8")

        final = intermediates[-1][1] if intermediates else ""
        print_chain_result(intermediates, final)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "decode-chain")
def decode_chain_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Data to decode through chain."),
    ] = None,
    steps: Annotated[
        str,
        typer.Option(
            "--steps",
            "-s",
            help = ("Comma-separated encoding formats in ENCODE order; "
                    "decoding is applied in reverse."),
        ),
    ] = "base64",
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help = "Write the final decoded output to file.",
        ),
    ] = None,
) -> None:
    try:
        text = resolve_input_text(data, file)
        formats = _parse_chain_steps(steps)
        intermediates: list[tuple[EncodingFormat, bytes]] = []
        current = text

        reversed_formats = list(reversed(formats))
        for index, step_fmt in enumerate(reversed_formats):
            decoded = decode(current, step_fmt)
            intermediates.append((step_fmt, decoded))
            if index < len(reversed_formats) - 1:
                try:
                    current = decoded.decode("utf-8")
                except UnicodeDecodeError:
                    raise typer.BadParameter(
                        f"Intermediate output after {step_fmt.value} decode "
                        "is not valid UTF-8; cannot continue the chain."
                    ) from None

        final = intermediates[-1][1] if intermediates else b""

        if output is not None:
            _write_output(output, final)
            return
        print_decode_chain_result(intermediates, final)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "hexdump")
def hexdump_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Encoded data to decode and dump."),
    ] = None,
    fmt: Annotated[
        EncodingFormat,
        typer.Option(
            "--format",
            "-f",
            help = "Source encoding format to decode before dumping.",
        ),
    ] = EncodingFormat.BASE64,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
) -> None:
    try:
        text = resolve_input_text(data, file)
        decoded = decode(text, fmt)
        print_hexdump(decoded)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "analyze")
def analyze_cmd(
    file: Annotated[
        Path | None,
        typer.Argument(help = "File of encoded samples, one per line."),
    ] = None,
    json_out: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Emit the report as JSON.",
        ),
    ] = False,
) -> None:
    try:
        if file is not None:
            if not file.exists():
                raise typer.BadParameter(f"File not found: {file}")
            lines = file.read_text("utf-8").splitlines()
        elif not sys.stdin.isatty():
            lines = sys.stdin.read().splitlines()
        else:
            raise typer.BadParameter(
                "No input provided. Pass a file argument or pipe stdin."
            )

        report = analyze_samples(lines)
        if json_out:
            print_json(json.dumps(report_to_dict(report), indent = 2))
            return
        print_analysis(report)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "entropy")
def entropy_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Data to measure entropy of."),
    ] = None,
    fmt: Annotated[
        EncodingFormat | None,
        typer.Option(
            "--format",
            "-f",
            help = "Decode with this format before measuring (default: auto).",
        ),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
) -> None:
    try:
        text = resolve_input_text(data, file)
        input_bytes = text.encode("utf-8")

        if fmt is not None:
            decoded = decode(text, fmt)
        else:
            best = detect_best(text)
            decoded = best.decoded if best is not None else None

        report = analyze_entropy(input_bytes, decoded)
        print_entropy(report)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


@app.command(name = "recipe")
def recipe_cmd(
    data: Annotated[
        str | None,
        typer.Argument(help = "Input data for the recipe."),
    ] = None,
    import_recipe: Annotated[
        Path | None,
        typer.Option(
            "--import",
            "-I",
            help = "CyberChef recipe JSON file to run.",
        ),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-i",
            help = "Read input from file.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help = "Write the final result to file.",
        ),
    ] = None,
) -> None:
    try:
        if import_recipe is None:
            raise typer.BadParameter("A recipe file is required (--import).")
        if not import_recipe.exists():
            raise typer.BadParameter(f"File not found: {import_recipe}")

        operations = parse_recipe(import_recipe.read_text("utf-8"))
        raw = resolve_input_bytes(data, file)
        steps, final = execute_recipe(operations, raw)

        if output is not None:
            _write_output(output, final)
            return
        print_recipe_result(steps, final)
    except typer.BadParameter:
        raise
    except Exception as exc:
        _console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code = ExitCode.ERROR) from None


def _parse_chain_steps(raw: str) -> list[EncodingFormat]:
    formats: list[EncodingFormat] = []
    valid_names = ", ".join(f.value for f in EncodingFormat)

    for step in raw.split(","):
        cleaned = step.strip().lower()
        try:
            formats.append(EncodingFormat(cleaned))
        except ValueError:
            raise typer.BadParameter(
                f"Unknown format '{cleaned}'. "
                f"Valid formats: {valid_names}"
            ) from None

    if not formats:
        raise typer.BadParameter("At least one step is required.")

    return formats
