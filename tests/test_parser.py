"""Tests for turning raw emails into ParsedEmail objects."""

import hashlib
from pathlib import Path

from phishcheck.parser import parse_eml
from tests.helpers import make_email

SAMPLES = Path(__file__).parent.parent / "samples"


def test_sender_fields_are_split_and_lowercased():
    email = make_email(from_="Northwind Bank <Alerts@NorthwindBank.Example>")

    assert email.from_display == "Northwind Bank"
    assert email.from_address == "alerts@northwindbank.example"
    assert email.from_domain == "northwindbank.example"


def test_auth_results_are_read_from_header():
    email = make_email(auth="mx.test; spf=softfail smtp.mailfrom=x.example; dkim=none; dmarc=fail")

    assert email.auth_results == {"spf": "softfail", "dkim": "none", "dmarc": "fail"}


def test_missing_auth_header_means_none():
    email = make_email(auth=None)

    assert email.auth_results == {"spf": "none", "dkim": "none", "dmarc": "none"}


def test_html_link_keeps_text_and_target_separately():
    email = make_email(html='<a href="http://203.0.113.9/login">https://bank.example/login</a>')

    assert len(email.links) == 1
    assert email.links[0].url == "http://203.0.113.9/login"
    assert email.links[0].text == "https://bank.example/login"


def test_plain_text_urls_are_found():
    email = make_email(text="Go to https://example.org/page now. Or http://example.net")

    assert [link.url for link in email.links] == ["https://example.org/page", "http://example.net"]


def test_same_url_in_text_and_html_is_listed_once_with_its_text():
    email = make_email(
        text="Visit https://bank.example/statements",
        html='<a href="https://bank.example/statements">View statement</a>',
    )

    assert len(email.links) == 1
    assert email.links[0].text == "View statement"


def test_attachments_are_hashed_not_opened():
    data = b"harmless test bytes"
    email = make_email(attachments=[("report.pdf", data)])

    attachment = email.attachments[0]
    assert attachment.filename == "report.pdf"
    assert attachment.size == len(data)
    assert attachment.sha256 == hashlib.sha256(data).hexdigest()


def test_sample_phish_is_parsed():
    email = parse_eml(SAMPLES / "credential_phish.eml")

    assert email.reply_to == "northwind.recovery.team@freemail.example"
    assert email.received_hops == 2
    assert email.auth_results["dmarc"] == "fail"


def test_forged_auth_header_lower_down_is_ignored():
    # The receiving server's verdict is the topmost header. A second header
    # further down was planted by the sender and must not override it.
    from email.message import EmailMessage
    from phishcheck.parser import parse_message

    message = EmailMessage()
    message["Authentication-Results"] = "mx.real; spf=fail; dkim=none; dmarc=fail"
    message["Authentication-Results"] = "mx.fake; spf=pass; dkim=pass; dmarc=pass"
    message["From"] = "a@b.example"
    message.set_content("hi")

    assert parse_message(message).auth_results == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
