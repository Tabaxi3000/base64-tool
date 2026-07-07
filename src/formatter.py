"""
formatter.py

Rich terminal output for all CLI commands

Handles all display logic for encoded strings, decoded bytes,
detection tables, peel layer summaries, and chain step results.
Detects whether stdout is a TTY or a pipe and switches between
Rich-formatted panels and raw text output. All Rich output goes
to stderr so piped stdout stays machine-readable.

Key exports:
  print_encoded() - Displays an encoded string in a Rich panel or raw to stdout
  print_decoded() - Displays decoded bytes as text or hex fallback, with file type
  print_detection() - Renders a confidence table for detect results
  print_peel_result() - Renders each peel layer and a final output panel
  print_chain_result() - Renders each encoding step and the final chain result
  print_score_breakdown() - Renders per-format score table for verbose mode
  detection_to_json() / peel_result_to_json() - JSON serialization for -j mode
  format_hexdump() / print_hexdump() - Traditional offset/hex/ASCII dump
  print_entropy() - Renders an entropy report
  print_analysis() - Renders bulk-detection statistics
  print_recipe_result() - Renders CyberChef recipe execution steps
  is_piped() - Returns True when stdout is not a TTY

Connects to:
  constants.py - imports CONFIDENCE_THRESHOLD, PREVIEW_LENGTH, EncodingFormat
  detector.py - imports DetectionResult
  peeler.py - imports PeelResult
  magic.py - imports identify_file_type
  entropy.py - imports EntropyReport
  analyze.py - imports AnalysisReport
  recipe.py - imports RecipeStep
  utils.py - imports safe_bytes_preview
  cli.py - imports all print_* functions
"""

import json
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from base64_tool.analyze import AnalysisReport
from base64_tool.constants import (
    CONFIDENCE_THRESHOLD,
    EncodingFormat,
    PREVIEW_LENGTH,
)
from base64_tool.detector import DetectionResult
from base64_tool.entropy import EntropyReport
from base64_tool.magic import identify_file_type
from base64_tool.peeler import PeelResult
from base64_tool.recipe import RecipeStep
from base64_tool.utils import safe_bytes_preview


console = Console(stderr = True)


def is_piped() -> bool:
    return not sys.stdout.isatty()


def write_raw(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def print_encoded(result: str, fmt: EncodingFormat) -> None:
    if is_piped():
        write_raw(result)
        return
    panel = Panel(
        Text(result,
             style = "green"),
        title = f"[bold cyan]{fmt.value}[/bold cyan] encoded",
        border_style = "cyan",
    )
    console.print(panel)


def print_decoded(result: bytes, *, detect_file_type: bool = True) -> None:
    file_type = identify_file_type(result) if detect_file_type else None
    preview = safe_bytes_preview(result, length = 4096)
    if is_piped():
        write_raw(preview)
        if file_type is not None:
            console.print(
                f"[dim]Detected file type:[/dim] "
                f"[magenta]{file_type.name}[/magenta]"
            )
        return
    subtitle = (
        f"[magenta]{file_type.name}[/magenta]"
        if file_type is not None
        else None
    )
    panel = Panel(
        Text(preview,
             style = "green"),
        title = "[bold cyan]Decoded[/bold cyan]",
        border_style = "cyan",
        subtitle = subtitle,
    )
    console.print(panel)


def print_score_breakdown(
    scores: dict[EncodingFormat,
                 float],
) -> None:
    table = Table(
        title = "Score Breakdown",
        show_header = True,
        header_style = "bold magenta",
    )
    table.add_column("Format", style = "cyan", min_width = 10)
    table.add_column(
        "Score",
        justify = "right",
        min_width = 8,
    )
    table.add_column("Status", min_width = 10)

    sorted_scores = sorted(
        scores.items(),
        key = lambda x: x[1],
        reverse = True,
    )
    for fmt, score in sorted_scores:
        color = _confidence_color(score)
        if score >= CONFIDENCE_THRESHOLD:
            status = "[green]detected[/green]"
        elif score > 0:
            status = "[yellow]below threshold[/yellow]"
        else:
            status = "[dim]no match[/dim]"
        table.add_row(
            fmt.value,
            f"[{color}]{score:.0%}[/{color}]",
            status,
        )

    console.print(table)


def print_detection(
    results: list[DetectionResult],
    *,
    verbose_scores: dict[EncodingFormat,
                         float] | None = None,
) -> None:
    if verbose_scores is not None:
        print_score_breakdown(verbose_scores)
        console.print()

    if not results:
        console.print("[yellow]No encoding format detected.[/yellow]")
        return

    table = Table(
        title = "Detection Results",
        show_header = True,
        header_style = "bold magenta",
    )
    table.add_column("Format", style = "cyan", min_width = 10)
    table.add_column(
        "Confidence",
        justify = "right",
        style = "green",
        min_width = 12,
    )
    table.add_column("Decoded Preview", style = "dim")

    for result in results:
        confidence_str = f"{result.confidence:.0%}"
        preview = ""
        if result.decoded is not None:
            preview = safe_bytes_preview(
                result.decoded,
                PREVIEW_LENGTH,
            )
        table.add_row(
            result.format.value,
            confidence_str,
            preview,
        )

    console.print(table)


def print_peel_result(
    result: PeelResult,
    *,
    verbose: bool = False,
) -> None:
    if not result.success:
        console.print("[yellow]No encoding layers detected.[/yellow]")
        return

    layer_count = len(result.layers)
    suffix = "s" if layer_count > 1 else ""
    console.print()
    console.print(
        f"[bold cyan]Peeled {layer_count} encoding "
        f"layer{suffix}[/bold cyan]"
    )
    console.print()

    for layer in result.layers:
        color = _confidence_color(layer.confidence)
        console.print(
            f"  [bold]Layer {layer.depth}[/bold]  "
            f"[cyan]{layer.format.value}[/cyan]  "
            f"[{color}]{layer.confidence:.0%}[/{color}]"
        )
        console.print(f"    [dim]{layer.decoded_preview}[/dim]")

        if verbose and layer.all_scores:
            console.print()
            print_score_breakdown(dict(layer.all_scores))
            console.print()

    console.print()

    preview = safe_bytes_preview(result.final_output, length = 4096)
    file_type = identify_file_type(result.final_output)
    subtitle = f"[dim]{layer_count} layer{suffix} peeled[/dim]"
    if file_type is not None:
        subtitle += f"  [magenta]{file_type.name}[/magenta]"
    panel = Panel(
        Text(preview,
             style = "bold green"),
        title = "[bold]Final Output[/bold]",
        border_style = "green",
        subtitle = subtitle,
    )
    console.print(panel)


def print_chain_result(
    steps: list[tuple[EncodingFormat,
                      str]],
    final: str,
) -> None:
    if is_piped():
        write_raw(final)
        return

    console.print()
    console.print("[bold cyan]Encoding Chain[/bold cyan]")
    console.print()

    for i, (fmt, intermediate) in enumerate(steps):
        marker = "start" if i == 0 else "step"
        arrow = f"  [{marker}] " if i == 0 else "    -> "
        truncated = intermediate[: PREVIEW_LENGTH]
        ellipsis = "..." if len(intermediate) > PREVIEW_LENGTH else ""
        console.print(
            f"{arrow}[cyan]{fmt.value}[/cyan]  "
            f"[dim]{truncated}{ellipsis}[/dim]"
        )

    console.print()
    panel = Panel(
        Text(final,
             style = "green"),
        title = "[bold]Chain Result[/bold]",
        border_style = "cyan",
        subtitle = f"[dim]{len(steps)} steps[/dim]",
    )
    console.print(panel)


def print_decode_chain_result(
    steps: list[tuple[EncodingFormat,
                      bytes]],
    final: bytes,
) -> None:
    if is_piped():
        write_raw(safe_bytes_preview(final, length = 4096))
        return

    console.print()
    console.print("[bold cyan]Decode Chain[/bold cyan]")
    console.print()

    for index, (fmt, decoded) in enumerate(steps, start = 1):
        preview = safe_bytes_preview(decoded, PREVIEW_LENGTH)
        console.print(
            f"  [dim]step {index}[/dim] "
            f"[cyan]{fmt.value}[/cyan] decode  "
            f"[dim]{preview}[/dim]"
        )

    console.print()
    file_type = identify_file_type(final)
    subtitle = f"[dim]{len(steps)} steps[/dim]"
    if file_type is not None:
        subtitle += f"  [magenta]{file_type.name}[/magenta]"
    panel = Panel(
        Text(safe_bytes_preview(final, length = 4096), style = "green"),
        title = "[bold]Decode Chain Result[/bold]",
        border_style = "cyan",
        subtitle = subtitle,
    )
    console.print(panel)


def _confidence_color(confidence: float) -> str:
    if confidence >= 0.9:
        return "green"
    if confidence >= 0.7:
        return "yellow"
    return "red"


def detection_to_json(results: list[DetectionResult]) -> str:
    payload = {
        "results": [
            {
                "format": result.format.value,
                "confidence": result.confidence,
                "decoded_preview": (
                    safe_bytes_preview(result.decoded, PREVIEW_LENGTH)
                    if result.decoded is not None
                    else None
                ),
            }
            for result in results
        ],
    }
    return json.dumps(payload, indent = 2)


def peel_result_to_json(result: PeelResult) -> str:
    file_type = identify_file_type(result.final_output)
    payload = {
        "success": result.success,
        "layer_count": len(result.layers),
        "layers": [
            {
                "depth": layer.depth,
                "format": layer.format.value,
                "confidence": layer.confidence,
                "decoded_preview": layer.decoded_preview,
            }
            for layer in result.layers
        ],
        "final_output": safe_bytes_preview(result.final_output, length = 4096),
        "final_file_type": file_type.name if file_type is not None else None,
    }
    return json.dumps(payload, indent = 2)


def print_json(text: str) -> None:
    write_raw(text + "\n")


def format_hexdump(data: bytes) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), 16):
        chunk = data[offset: offset + 16]
        hex_bytes = [f"{byte:02x}" for byte in chunk]
        left = " ".join(hex_bytes[: 8])
        right = " ".join(hex_bytes[8:])
        ascii_col = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in chunk
        )
        lines.append(
            f"{offset:08x}  {left:<23}  {right:<23}  |{ascii_col}|"
        )
    return "\n".join(lines)


def print_hexdump(data: bytes) -> None:
    dump = format_hexdump(data)
    if is_piped():
        write_raw(dump + "\n" if dump else "")
        return
    file_type = identify_file_type(data)
    subtitle = (
        f"[magenta]{file_type.name}[/magenta]"
        if file_type is not None
        else f"[dim]{len(data)} bytes[/dim]"
    )
    panel = Panel(
        Text(dump or "(no data)"),
        title = "[bold cyan]Hex Dump[/bold cyan]",
        border_style = "cyan",
        subtitle = subtitle,
    )
    console.print(panel)


def print_entropy(report: EntropyReport) -> None:
    table = Table(
        title = "Entropy Analysis",
        show_header = True,
        header_style = "bold magenta",
    )
    table.add_column("Stage", style = "cyan", min_width = 10)
    table.add_column("Entropy (0-8)", justify = "right", min_width = 12)

    table.add_row("input", f"{report.input_entropy:.3f}")
    if report.decoded_entropy is not None:
        table.add_row("decoded", f"{report.decoded_entropy:.3f}")

    console.print(table)
    console.print(f"[dim]Interpretation:[/dim] {report.interpretation}")
    if report.high_entropy:
        console.print(
            "[yellow]High entropy: data is likely encrypted or compressed, "
            "not merely encoded.[/yellow]"
        )


def print_analysis(report: AnalysisReport) -> None:
    table = Table(
        title = "Format Distribution",
        show_header = True,
        header_style = "bold magenta",
    )
    table.add_column("Format", style = "cyan", min_width = 10)
    table.add_column("Count", justify = "right", min_width = 6)
    table.add_column("Share", justify = "right", min_width = 7)
    table.add_column("Avg Confidence", justify = "right", min_width = 14)

    ordered = sorted(
        report.format_counts.items(),
        key = lambda item: item[1],
        reverse = True,
    )
    for fmt, count in ordered:
        share = count / report.total if report.total else 0.0
        avg = report.format_avg_confidence.get(fmt, 0.0)
        table.add_row(
            fmt.value,
            str(count),
            f"{share:.0%}",
            f"{avg:.0%}",
        )

    console.print(table)
    console.print(
        f"[bold]Total:[/bold] {report.total}   "
        f"[green]detected:[/green] {report.detected}   "
        f"[red]failures:[/red] {report.failures}   "
        f"[yellow]ambiguous:[/yellow] {report.ambiguous}"
    )

    ambiguous_samples = [s for s in report.samples if s.ambiguous]
    if ambiguous_samples:
        console.print()
        console.print("[yellow]Ambiguous samples (matched >1 format):[/yellow]")
        for sample in ambiguous_samples:
            formats = ", ".join(
                f"{fmt.value} {conf:.0%}" for fmt, conf in sample.matches
            )
            console.print(
                f"  [dim]line {sample.line_number}:[/dim] {formats}"
            )


def print_recipe_result(steps: list[RecipeStep], final: bytes) -> None:
    if is_piped():
        write_raw(safe_bytes_preview(final, length = 4096))
        return

    console.print()
    console.print("[bold cyan]Recipe Execution[/bold cyan]")
    console.print()

    for index, step in enumerate(steps, start = 1):
        direction = "decode" if step.operation.decode else "encode"
        truncated = step.output_preview[: PREVIEW_LENGTH]
        ellipsis = "..." if len(step.output_preview) > PREVIEW_LENGTH else ""
        console.print(
            f"  [dim]step {index}[/dim] "
            f"[cyan]{step.operation.op_name}[/cyan] ({direction})  "
            f"[dim]{truncated}{ellipsis}[/dim]"
        )

    console.print()
    panel = Panel(
        Text(safe_bytes_preview(final, length = 4096), style = "green"),
        title = "[bold]Recipe Result[/bold]",
        border_style = "cyan",
        subtitle = f"[dim]{len(steps)} operations[/dim]",
    )
    console.print(panel)