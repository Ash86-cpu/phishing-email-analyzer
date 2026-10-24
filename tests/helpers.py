"""Build test emails in memory, so each test shows exactly what it feeds in."""

from email.message import EmailMessage

from phishcheck.parser import parse_message

PASSING_AUTH = "mx.test; spf=pass; dkim=pass; dmarc=pass"


def make_email(
    from_="Northwind Bank <alerts@northwindbank.example>",
    subject="Hello",
    text="Just a normal message.",
    html=None,
    auth=PASSING_AUTH,
    reply_to=None,
    return_path=None,
    attachments=(),
):
    """Return a ParsedEmail. Defaults describe a clean, legitimate message."""
    message = EmailMessage()
    message["From"] = from_
    message["To"] = "you@mail.example"
    message["Subject"] = subject
    if auth:
        message["Authentication-Results"] = auth
    if reply_to:
        message["Reply-To"] = reply_to
    if return_path:
        message["Return-Path"] = return_path
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    for filename, data in attachments:
        message.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)
    return parse_message(message)
