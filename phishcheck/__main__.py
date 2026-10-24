"""Entry point: `python -m phishcheck <file.eml>`. For now, shows what was parsed."""

import sys
from pathlib import Path

from .parser import parse_eml


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m phishcheck <path-to-email.eml>")
        return 1

    email = parse_eml(Path(sys.argv[1]))

    print(f"Subject     : {email.subject}")
    print(f"From        : {email.from_display} <{email.from_address}>")
    print(f"Reply-To    : {email.reply_to or '-'}")
    print(f"Return-Path : {email.return_path or '-'}")
    auth = ", ".join(f"{k.upper()}={v}" for k, v in email.auth_results.items())
    print(f"Auth        : {auth}")
    print(f"Relay hops  : {email.received_hops}")

    print(f"\nLinks ({len(email.links)}):")
    for link in email.links:
        shown = f'  text "{link.text}"' if link.text else ""
        print(f"  {link.url}{shown}")

    print(f"\nAttachments ({len(email.attachments)}):")
    for a in email.attachments:
        print(f"  {a.filename}  {a.content_type}  {a.size} bytes")
        print(f"    sha256 {a.sha256}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
