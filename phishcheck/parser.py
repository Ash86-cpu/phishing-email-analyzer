"""Turn a raw .eml file into a ParsedEmail.

Uses only Python's standard library: the `email` package understands MIME,
encodings and multipart messages, so we don't hand-parse any of that.
"""

import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional

from .models import Attachment, Link, ParsedEmail

# Plain-text URLs: http(s)://, up to the first whitespace or bracket/quote.
URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# "spf=fail", "dkim=pass", "dmarc=none" inside Authentication-Results headers.
AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


class _LinkExtractor(HTMLParser):
    """Collect every <a href="..."> together with the text shown to the reader."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[Link] = []
        self._href: Optional[str] = None
        self._text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            text = " ".join("".join(self._text).split())
            self.links.append(Link(url=self._href.strip(), text=text or None))
            self._href = None


class _TextExtractor(HTMLParser):
    """Strip tags from HTML so the body can be searched as plain text."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: List[str] = []

    def handle_data(self, data):
        self.parts.append(data)


def parse_auth_results(message: EmailMessage) -> Dict[str, str]:
    """Read SPF/DKIM/DMARC verdicts that the receiving mail server recorded.

    We trust only the receiving server's verdict here; we don't redo the DNS
    lookups ourselves. A missing result is reported as "none".
    """
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for header in message.get_all("Authentication-Results", []):
        for mechanism, verdict in AUTH_PATTERN.findall(str(header)):
            results[mechanism.lower()] = verdict.lower()
    return results


def parse_eml(path: Path) -> ParsedEmail:
    with open(path, "rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)
    return parse_message(message)


def parse_message(message: EmailMessage) -> ParsedEmail:
    from_display, from_address = parseaddr(str(message.get("From", "")))
    _, reply_to = parseaddr(str(message.get("Reply-To", "")))
    _, return_path = parseaddr(str(message.get("Return-Path", "")))

    text_parts: List[str] = []
    links: List[Link] = []
    attachments: List[Attachment] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        if part.is_attachment():
            payload = part.get_payload(decode=True) or b""
            attachments.append(Attachment(
                filename=part.get_filename() or "(unnamed)",
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ))
            continue

        content_type = part.get_content_type()
        if content_type == "text/plain":
            text = part.get_content()
            text_parts.append(text)
            links += [Link(url=url, text=None) for url in URL_PATTERN.findall(text)]
        elif content_type == "text/html":
            html = part.get_content()
            link_parser = _LinkExtractor()
            link_parser.feed(html)
            links += link_parser.links
            text_parser = _TextExtractor()
            text_parser.feed(html)
            text_parts.append(" ".join(text_parser.parts))

    return ParsedEmail(
        subject=str(message.get("Subject", "")),
        from_display=from_display,
        from_address=from_address.lower(),
        reply_to=reply_to.lower() or None,
        return_path=return_path.lower() or None,
        auth_results=parse_auth_results(message),
        received_hops=len(message.get_all("Received", [])),
        body_text="\n".join(text_parts),
        links=_deduplicate(links),
        attachments=attachments,
    )


def _deduplicate(links: List[Link]) -> List[Link]:
    """Keep the first occurrence of each URL, preferring the one with link text."""
    seen = {}
    for link in links:
        if link.url not in seen or (seen[link.url].text is None and link.text):
            seen[link.url] = link
    return list(seen.values())
