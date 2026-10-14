import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from rich.console import Console
from rich.text import Text

from .model import MAX_INPUT, normalize, read_json
from .render import terminal, webpage


def write_new(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Readable terminal/HTML views of WPScan JSON.")
    parser.add_argument("input", nargs="?", default="-", help="JSON file, '-' for stdin, or 'scan' to run WPScan")
    parser.add_argument("--html", metavar="FILE", help="Also save a standalone HTML report (new file)")
    parser.add_argument("--json", metavar="FILE", help="Also save normalized, redacted JSON (new file)")
    parser.add_argument("--command-line", help="Supply original command when an older JSON report omitted it")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--details", action="store_true", help="Include full component evidence in the terminal")
    parser.add_argument("--wpscan-bin", default="wpscan", help="Executable for scan mode")
    # Everything after '--' goes to WPScan, never to a shell.
    supplied = list(sys.argv[1:] if argv is None else argv)
    cut = supplied.index("--") if "--" in supplied else len(supplied)
    args = parser.parse_args(supplied[:cut])
    forwarded = supplied[cut + 1:]
    console = Console(no_color=args.no_color or bool(os.getenv("NO_COLOR")), highlight=False)
    try:
        for output in (args.html, args.json):
            if output and Path(output).exists():
                raise ValueError("Output already exists; choose a new filename.")
        if args.html and args.json and Path(args.html).resolve() == Path(args.json).resolve():
            raise ValueError("HTML and JSON need different filenames.")
        status = 0
        if args.input == "scan":
            if not forwarded:
                raise ValueError("Usage: wpscan-view scan [--html report.html] -- --url https://example.test -e vp,vt")
            if any(a in ("-o", "--output", "-f", "--format") or a.startswith(("--output=", "--format="))
                   or (a.startswith(("-o", "-f")) and not a.startswith("--")) for a in forwarded):
                raise ValueError("scan mode manages WPScan output/format; remove -o/-f and use --html or --json before '--'.")
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                result = subprocess.run([args.wpscan_bin, *forwarded, "--format", "json"],
                    stdout=output, stderr=errors, check=False)
                output.seek(0)
                raw = read_json(output)
            status = result.returncode
            report = normalize(raw, forwarded)
            if status:
                report["warnings"].append(f"WPScan exited with status {status}; review partial findings.")
        else:
            if forwarded:
                raise ValueError("Arguments after '--' require the scan subcommand.")
            if args.input == "-":
                raw = read_json(sys.stdin.buffer)
            else:
                with Path(args.input).open("rb") as stream:
                    raw = read_json(stream)
            report = normalize(raw, args.command_line)
            if raw.get("scan_aborted") or raw.get("update_aborted"):
                status = 1
        terminal(report, console)
        if args.details:
            for c in report["components"]:
                console.print(Text(json.dumps(c["evidence"], ensure_ascii=False, indent=2)))
        if args.html:
            write_new(args.html, webpage(report))
            console.print(Text("HTML saved: " + args.html, style="green"))
        if args.json:
            write_new(args.json, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return status if 0 <= status <= 125 else 1
    except (ValueError, OSError, RecursionError) as exc:
        Console(stderr=True, no_color=True).print(Text("Error: " + str(exc)))
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
