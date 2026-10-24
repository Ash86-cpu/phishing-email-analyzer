"""Command-line interface: `python -m phishcheck <file.eml> [more.eml ...]`."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .checks import analyse, verdict
from .parser import parse_eml


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishcheck",
        description="Score raw .eml emails for signs of phishing.",
    )
    parser.add_argument("emails", nargs="+", type=Path, help="one or more .eml files")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="output format (default: text)",
    )
    return parser


def analyse_file(path: Path) -> dict:
    email = parse_eml(path)
    findings = analyse(email)
    score = sum(f.score for f in findings)
    return {
        "file": str(path),
        "subject": email.subject,
        "from": f"{email.from_display} <{email.from_address}>",
        "score": score,
        "verdict": verdict(score),
        "findings": [asdict(f) for f in sorted(findings, key=lambda f: -f.score)],
        "attachments": [asdict(a) for a in email.attachments],
    }


def print_text(result: dict) -> None:
    print(f"{result['verdict']}  (score {result['score']})  {result['file']}")
    print(f"  From    : {result['from']}")
    print(f"  Subject : {result['subject']}")
    for f in result["findings"]:
        tag = f"  [{f['mitre'].split()[0]}]" if f["mitre"] else ""
        print(f"  +{f['score']:<2} {f['description']}{tag}")
    print()


def main() -> int:
    args = build_parser().parse_args()

    missing = [p for p in args.emails if not p.is_file()]
    if missing:
        print(f"error: file not found: {missing[0]}", file=sys.stderr)
        return 1

    results = [analyse_file(path) for path in args.emails]
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print_text(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
