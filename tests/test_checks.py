"""Tests for the phishing checks and the verdict.

As in the log detector, every rule is tested both ways: it fires on the
phishing pattern, and it stays quiet on the ordinary version of the same thing.
"""

from pathlib import Path

from phishcheck.checks import (
    analyse,
    base_domain,
    check_attachments,
    check_authentication,
    check_links,
    check_pressure_language,
    check_sender,
    verdict,
)
from phishcheck.parser import parse_eml
from tests.helpers import make_email

SAMPLES = Path(__file__).parent.parent / "samples"


def names(findings):
    return [f.check for f in findings]


# --- authentication --------------------------------------------------------

def test_passing_authentication_adds_nothing():
    assert check_authentication(make_email()) == []


def test_failed_authentication_is_scored():
    email = make_email(auth="mx.test; spf=fail; dkim=pass; dmarc=fail")

    assert sorted(names(check_authentication(email))) == ["dmarc_fail", "spf_fail"]


# --- sender ----------------------------------------------------------------

def test_reply_to_another_domain_is_flagged():
    email = make_email(reply_to="help@freemail.example")

    assert names(check_sender(email)) == ["reply_to_mismatch"]


def test_reply_to_a_subdomain_of_the_sender_is_fine():
    email = make_email(reply_to="support@help.northwindbank.example")

    assert check_sender(email) == []


def test_address_faked_in_display_name_is_flagged():
    email = make_email(from_='"support@northwindbank.example" <x@evil.example>')

    assert "display_name_spoof" in names(check_sender(email))


# --- links -----------------------------------------------------------------

def test_link_text_pointing_elsewhere_is_flagged():
    email = make_email(html='<a href="https://evil.example/login">https://northwindbank.example/login</a>')

    assert "link_text_mismatch" in names(check_links(email))


def test_ordinary_link_text_is_not_a_mismatch():
    # "Click here" isn't a URL, so there is nothing to compare.
    email = make_email(html='<a href="https://northwindbank.example/offers">Click here</a>')

    assert check_links(email) == []


def test_ip_address_link_is_flagged():
    assert "ip_address_link" in names(check_links(make_email(text="Log in: http://203.0.113.45/a")))


def test_punycode_link_is_flagged():
    email = make_email(text="Visit https://xn--nrthwind-9za.example/login")

    assert "punycode_link" in names(check_links(email))


def test_userinfo_trick_is_flagged():
    email = make_email(text="Visit https://northwindbank.example@evil.example/login")

    assert "userinfo_link" in names(check_links(email))


def test_url_shortener_is_flagged():
    assert "shortened_link" in names(check_links(make_email(text="See https://bit.ly/abc123")))


# --- attachments -----------------------------------------------------------

def test_double_extension_is_flagged():
    email = make_email(attachments=[("Invoice.pdf.exe", b"x")])

    assert names(check_attachments(email)) == ["double_extension"]


def test_executable_attachment_is_flagged():
    email = make_email(attachments=[("setup.exe", b"x")])

    assert names(check_attachments(email)) == ["dangerous_attachment"]


def test_normal_document_is_not_flagged():
    email = make_email(attachments=[("Quarterly.Report.2026.pdf", b"x")])

    assert check_attachments(email) == []


def test_attachment_findings_carry_attack_technique():
    email = make_email(attachments=[("payload.js", b"x")])

    assert check_attachments(email)[0].mitre.startswith("T1566.001")


# --- wording ---------------------------------------------------------------

def test_pressure_language_needs_two_phrases():
    one = make_email(subject="Your password was changed")
    two = make_email(subject="URGENT: verify your password")

    assert check_pressure_language(one) == []
    assert names(check_pressure_language(two)) == ["pressure_language"]


# --- helpers and verdict ---------------------------------------------------

def test_base_domain_keeps_last_two_labels():
    assert base_domain("mail.northwindbank.example") == "northwindbank.example"


def test_verdict_thresholds():
    assert verdict(0) == "NO STRONG INDICATORS"
    assert verdict(2) == "NO STRONG INDICATORS"
    assert verdict(3) == "SUSPICIOUS"
    assert verdict(7) == "SUSPICIOUS"
    assert verdict(8) == "LIKELY PHISHING"


def test_clean_email_scores_zero():
    assert analyse(make_email()) == []


def score_of(sample):
    return sum(f.score for f in analyse(parse_eml(SAMPLES / sample)))


def test_sample_verdicts():
    assert verdict(score_of("legitimate.eml")) == "NO STRONG INDICATORS"
    assert verdict(score_of("newsletter.eml")) == "SUSPICIOUS"
    assert verdict(score_of("credential_phish.eml")) == "LIKELY PHISHING"
    assert verdict(score_of("malicious_attachment.eml")) == "LIKELY PHISHING"
