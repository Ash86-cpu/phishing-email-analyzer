"""Data structures produced by the parser and consumed by the checks."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Link:
    """A URL found in the email body."""

    url: str             # where the link actually goes
    text: Optional[str]  # what the reader sees (HTML links only), e.g. "Log in"


@dataclass(frozen=True)
class Attachment:
    """A file attached to the email. We hash it but never open or run it."""

    filename: str
    content_type: str
    size: int            # bytes
    sha256: str          # fingerprint, searchable on VirusTotal and similar


@dataclass
class ParsedEmail:
    """Everything the checks need, pulled out of one raw .eml file."""

    subject: str
    from_display: str            # the friendly name, e.g. "Northwind Bank"
    from_address: str            # the actual address, e.g. alerts@evil.example
    reply_to: Optional[str]      # where replies go, if different
    return_path: Optional[str]   # where bounces go (the "envelope sender")
    auth_results: Dict[str, str] # {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    received_hops: int           # how many servers relayed the message
    body_text: str
    links: List[Link] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_address)


def domain_of(address: Optional[str]) -> str:
    """'Alice <alice@Mail.Example.com>' or 'alice@mail.example.com' -> 'mail.example.com'."""
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip(" >").lower()
