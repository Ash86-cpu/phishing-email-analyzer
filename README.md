# phishing-email-analyzer

[![tests](https://github.com/Ash86-cpu/phishing-email-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/Ash86-cpu/phishing-email-analyzer/actions/workflows/tests.yml)

A Python command-line tool that reads raw `.eml` email files and scores them for
signs of phishing: failed sender authentication, spoofed senders, deceptive
links and dangerous attachments. Each finding explains itself and, where it
applies, is mapped to [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/).

It automates the first-pass triage a SOC analyst does when a user reports a
suspicious email.

Only the Python standard library is needed to run it.

## Quick start

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Ash86-cpu/phishing-email-analyzer.git
cd phishing-email-analyzer

python -m phishcheck samples/credential_phish.eml
python -m phishcheck samples/*.eml              # several at once
python -m phishcheck samples/legitimate.eml --format json
```

To analyse a real email, save it from your mail client as a `.eml` file
(in Outlook: File > Save As; in Gmail: More > Download message).

## Example output

```
$ python -m phishcheck samples/credential_phish.eml
LIKELY PHISHING  (score 22)  samples/credential_phish.eml
  From    : Northwind Bank Security <security@northwind-bank-alerts.example>
  Subject : URGENT: Unusual sign-in activity - account suspended in 24 hours
  +4  DMARC result is 'fail' for this message
  +4  Link shows 'https://www.northwindbank.example/login' but actually goes to http://203.0.113.45/nwb/login.php  [T1566.002]
  +3  SPF result is 'fail' for this message
  +3  Replies go to northwind.recovery.team@freemail.example, not to the sender's domain northwind-bank-alerts.example
  +3  Link points to a raw IP address instead of a domain: http://203.0.113.45/nwb/login.php  [T1566.002]
  +2  Urgent or credential-seeking wording: urgent, immediately, suspended, within 24 hours, unusual sign-in, verify your, password, account will be
  +1  DKIM result is 'none' for this message
  +1  Envelope sender bounce@mailer.badhost.example differs from From domain northwind-bank-alerts.example
  +1  Link does not use HTTPS: http://203.0.113.45/nwb/login.php
```

## What it checks

| Area | Check | Points | ATT&CK |
|---|---|---|---|
| Authentication | DMARC fail / none | 4 / 1 | |
| | SPF fail / softfail / none | 3 / 2 / 1 | |
| | DKIM fail / none | 3 / 1 | |
| Sender | Reply-To goes to a different domain | 3 | |
| | An email address faked in the display name | 3 | |
| | Envelope sender (Return-Path) differs from From | 1 | |
| Links | Visible link text shows one site, link goes to another | 4 | T1566.002 |
| | Link to a raw IP address | 3 | T1566.002 |
| | Punycode (`xn--`) lookalike domain | 3 | T1566.002 |
| | Real host hidden after `@` (`https://bank.example@evil.example`) | 3 | T1566.002 |
| | URL shortener | 2 | T1566.002 |
| | Link without HTTPS | 1 | |
| Attachments | Double extension, e.g. `invoice.pdf.exe` | 5 | T1566.001 |
| | Executable or macro file type | 4 | T1566.001 |
| | HTML attachment (often a fake login page) | 3 | T1566.001 |
| | Archive (`.zip`, `.rar`, ...) | 1 | T1566.001 |
| Wording | Two or more urgency or credential phrases | 2 | |

The points are added up into a verdict:

| Total | Verdict |
|---|---|
| 0 to 2 | NO STRONG INDICATORS |
| 3 to 7 | SUSPICIOUS |
| 8 or more | LIKELY PHISHING |

## Sample results

| Sample | What it is | Score | Verdict |
|---|---|---|---|
| `legitimate.eml` | A real bank statement notice, all checks pass | 0 | NO STRONG INDICATORS |
| `newsletter.eml` | A real marketing email sent via a mailing service, with a shortened link | 3 | SUSPICIOUS |
| `credential_phish.eml` | Fake security alert linking to a login page on a bare IP | 22 | LIKELY PHISHING |
| `malicious_attachment.eml` | Fake overdue invoice with `Invoice_10442.pdf.exe` and an HTML attachment | 16 | LIKELY PHISHING |

The newsletter is a deliberate grey-zone case: it is legitimate, but it shares
two habits with phishing (shortened links and a third-party sending service).
It shows the trade-off every scoring system makes between catching more
phishing and raising more false alarms.

## How it works

```
.eml file  ->  parser.py  ->  ParsedEmail  ->  checks.py  ->  findings + score  ->  verdict
```

| File | Responsibility |
|---|---|
| `phishcheck/parser.py` | Uses Python's `email` package to read headers, auth results, links (keeping link text and target separate) and attachments |
| `phishcheck/models.py` | `ParsedEmail`, `Link` and `Attachment` data classes |
| `phishcheck/checks.py` | The checks, their weights, and the verdict thresholds |
| `phishcheck/__main__.py` | Command-line interface with text and JSON output |

Design decisions:

- **Score, don't decide on one clue.** Legitimate mail sometimes fails SPF
  (forwarding breaks it) or uses a mailing service. Adding weighted findings
  means one odd detail cannot condemn a message on its own.
- **Trust the receiving server's authentication verdicts.** SPF, DKIM and DMARC
  are read from the `Authentication-Results` header rather than re-checked,
  because DNS records can change after delivery.
- **Keep link text and link target apart.** The most reliable phishing signal is
  a link that displays one address and goes to another.
- **Never open attachments.** They are identified by name and type and
  fingerprinted with SHA-256, which an analyst can look up in threat
  intelligence services such as VirusTotal.
- **Weights and thresholds live in one place** in `checks.py`, so they can be
  tuned without touching the logic.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

28 tests cover the parser, every check and the verdicts on all four samples.
Each check is tested both ways: that it fires on the phishing pattern, and that
it stays quiet on the ordinary version (a reply address on the sender's own
subdomain, link text that just says "Click here", a document named
`Quarterly.Report.2026.pdf`). GitHub Actions runs the suite on Python 3.10 and
3.12 on every push.

## Limitations

This is a learning project and a triage aid, not a mail filter. Known gaps:

- It trusts the `Authentication-Results` header. On a server that does not
  strip incoming copies of that header, an attacker could forge it.
- Domain comparison keeps the last two labels of a domain, which is wrong for
  suffixes like `.co.uk`. A production tool would use the Public Suffix List.
- It does not detect lookalike domains that use ordinary letters
  (`northwind-bank-alerts.example`, `rnicrosoft.com`); only punycode lookalikes.
- It does not follow links, check URL or hash reputation, or look inside
  archives and documents.
- Wording checks are English-only keyword matches.
- Image-only emails and links inside attachments are not analysed.

## Sample data

All sample emails are synthetic. Northwind Bank is fictional, every domain
uses the reserved `.example` top-level domain, and IP addresses come from the
documentation ranges in RFC 5737, so nothing in this repository points to a
real organisation or live server. The "attachments" are short plain-text
placeholders, not real executables.

## License

MIT. See [LICENSE](LICENSE).
