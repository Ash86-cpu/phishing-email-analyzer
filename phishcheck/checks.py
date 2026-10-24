"""Phishing checks. Each check looks at one ParsedEmail and returns Findings.

Every finding carries a score. No single clue proves phishing (plenty of
legitimate mail fails SPF because of a forwarding service, for example), so
the verdict comes from adding the scores up, the same idea spam filters use.
The weights are judgement calls, kept in one place so they are easy to tune.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, List, Optional
from urllib.parse import urlsplit

from .models import ParsedEmail, domain_of


@dataclass(frozen=True)
class Finding:
    check: str                  # machine-readable name
    score: int                  # how much this clue adds to the total
    description: str            # one sentence for the analyst
    mitre: Optional[str] = None # ATT&CK technique, where one applies


# Phishing via a link vs via an attachment, in MITRE ATT&CK.
LINK_TECHNIQUE = "T1566.002 Phishing: Spearphishing Link"
ATTACHMENT_TECHNIQUE = "T1566.001 Phishing: Spearphishing Attachment"

AUTH_SCORES = {
    "spf": {"fail": 3, "softfail": 2, "none": 1},
    "dkim": {"fail": 3, "none": 1},
    "dmarc": {"fail": 4, "none": 1},
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly"}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".jar", ".msi", ".lnk", ".iso", ".img", ".docm", ".xlsm", ".pptm",
}
DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz"}

PRESSURE_PHRASES = [
    "urgent", "immediately", "suspended", "within 24 hours", "unusual sign-in",
    "verify your", "confirm your", "password", "account will be", "overdue",
    "payment required", "final notice", "action required",
]


def base_domain(domain: str) -> str:
    """'mail.northwindbank.example' -> 'northwindbank.example'.

    Simplification: keeps the last two labels, so it is wrong for suffixes
    like .co.uk. A production tool would use the Public Suffix List.
    """
    return ".".join(domain.lower().split(".")[-2:])


# --- sender authentication -------------------------------------------------

def check_authentication(email: ParsedEmail) -> List[Finding]:
    findings = []
    for mechanism, verdict in email.auth_results.items():
        score = AUTH_SCORES[mechanism].get(verdict, 0)
        if score:
            findings.append(Finding(
                check=f"{mechanism}_{verdict}",
                score=score,
                description=f"{mechanism.upper()} result is '{verdict}' for this message",
            ))
    return findings


# --- sender identity -------------------------------------------------------

def check_sender(email: ParsedEmail) -> List[Finding]:
    findings = []
    from_base = base_domain(email.from_domain)

    if email.reply_to and base_domain(domain_of(email.reply_to)) != from_base:
        findings.append(Finding(
            check="reply_to_mismatch",
            score=3,
            description=f"Replies go to {email.reply_to}, not to the sender's domain {email.from_domain}",
        ))

    if email.return_path and base_domain(domain_of(email.return_path)) != from_base:
        # Low score: newsletters sent through mailing services do this legitimately.
        findings.append(Finding(
            check="return_path_mismatch",
            score=1,
            description=f"Envelope sender {email.return_path} differs from From domain {email.from_domain}",
        ))

    shown = re.search(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", email.from_display)
    if shown and shown.group(0).lower() != email.from_address:
        findings.append(Finding(
            check="display_name_spoof",
            score=3,
            description=f"Display name shows {shown.group(0)} but the real sender is {email.from_address}",
        ))
    return findings


# --- links -----------------------------------------------------------------

def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _looks_like_url(text: str) -> bool:
    return bool(re.match(r"^(https?://)?[\w-]+(\.[\w-]+)+(/\S*)?$", text.strip()))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_links(email: ParsedEmail) -> List[Finding]:
    findings = []
    for link in email.links:
        host = _host(link.url)

        if link.text and _looks_like_url(link.text):
            shown_host = _host(link.text if "://" in link.text else "http://" + link.text)
            if shown_host and shown_host != host:
                findings.append(Finding(
                    check="link_text_mismatch", score=4, mitre=LINK_TECHNIQUE,
                    description=f"Link shows '{link.text}' but actually goes to {link.url}",
                ))

        if _is_ip(host):
            findings.append(Finding(
                check="ip_address_link", score=3, mitre=LINK_TECHNIQUE,
                description=f"Link points to a raw IP address instead of a domain: {link.url}",
            ))
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(Finding(
                check="punycode_link", score=3, mitre=LINK_TECHNIQUE,
                description=f"Link uses a punycode domain, often a lookalike of a real one: {host}",
            ))
        if "@" in (urlsplit(link.url).netloc or ""):
            findings.append(Finding(
                check="userinfo_link", score=3, mitre=LINK_TECHNIQUE,
                description=f"Link hides its real host after an '@': {link.url}",
            ))
        if host in URL_SHORTENERS:
            findings.append(Finding(
                check="shortened_link", score=2, mitre=LINK_TECHNIQUE,
                description=f"Link uses a URL shortener that hides the destination: {link.url}",
            ))
        if link.url.lower().startswith("http://"):
            findings.append(Finding(
                check="unencrypted_link", score=1,
                description=f"Link does not use HTTPS: {link.url}",
            ))
    return findings


# --- attachments -----------------------------------------------------------

def _extensions(filename: str) -> List[str]:
    parts = filename.lower().split(".")
    return ["." + p for p in parts[1:]]


def check_attachments(email: ParsedEmail) -> List[Finding]:
    findings = []
    for attachment in email.attachments:
        name = attachment.filename
        extensions = _extensions(name)
        last = extensions[-1] if extensions else ""

        if len(extensions) >= 2 and extensions[-2] in DECOY_EXTENSIONS and last in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                check="double_extension", score=5, mitre=ATTACHMENT_TECHNIQUE,
                description=f"'{name}' disguises a {last} file as a {extensions[-2]} (sha256 {attachment.sha256[:16]}...)",
            ))
        elif last in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                check="dangerous_attachment", score=4, mitre=ATTACHMENT_TECHNIQUE,
                description=f"'{name}' is a file type that can run code (sha256 {attachment.sha256[:16]}...)",
            ))
        elif last in (".html", ".htm"):
            findings.append(Finding(
                check="html_attachment", score=3, mitre=ATTACHMENT_TECHNIQUE,
                description=f"'{name}' is an HTML attachment, a common way to deliver fake login pages",
            ))
        elif last in ARCHIVE_EXTENSIONS:
            findings.append(Finding(
                check="archive_attachment", score=1, mitre=ATTACHMENT_TECHNIQUE,
                description=f"'{name}' is an archive, which can hide its contents from scanners",
            ))
    return findings


# --- wording ---------------------------------------------------------------

def check_pressure_language(email: ParsedEmail) -> List[Finding]:
    text = f"{email.subject}\n{email.body_text}".lower()
    found = [phrase for phrase in PRESSURE_PHRASES if phrase in text]
    if len(found) >= 2:
        return [Finding(
            check="pressure_language", score=2,
            description=f"Urgent or credential-seeking wording: {', '.join(found)}",
        )]
    return []


# --- verdict ---------------------------------------------------------------

ALL_CHECKS: List[Callable[[ParsedEmail], List[Finding]]] = [
    check_authentication,
    check_sender,
    check_links,
    check_attachments,
    check_pressure_language,
]

SUSPICIOUS_AT = 3
PHISHING_AT = 8


def analyse(email: ParsedEmail) -> List[Finding]:
    return [finding for check in ALL_CHECKS for finding in check(email)]


def verdict(score: int) -> str:
    if score >= PHISHING_AT:
        return "LIKELY PHISHING"
    if score >= SUSPICIOUS_AT:
        return "SUSPICIOUS"
    return "NO STRONG INDICATORS"
