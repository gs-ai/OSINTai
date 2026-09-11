"""Consume maximal tokens once; validate only protocol-sized candidates."""

import re

EMAIL_TOKEN = re.compile(r"[A-Za-z0-9._%+@-]+")
DOMAIN_TOKEN = re.compile(r"[A-Za-z0-9.-]+")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")
CREDENTIAL_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w.-]{1,253}\.[A-Za-z]{2,63}")
USER = re.compile(r"[\w.-]{3,32}")


def valid_domain(value):
    if len(value) > 253:
        return False
    labels = value.split(".")
    return (
        len(labels) >= 2
        and labels[-1].isascii()
        and labels[-1].isalpha()
        and 2 <= len(labels[-1]) <= 63
        and all(label and len(label) <= 63 and label[0] != "-" and label[-1] != "-" for label in labels)
    )


def emails(text):
    for match in EMAIL_TOKEN.finditer(text):
        value = match.group().strip(".")
        if len(value) <= 254 and EMAIL.fullmatch(value) and valid_domain(value.rsplit("@", 1)[1]):
            yield value


def domains(text):
    for match in DOMAIN_TOKEN.finditer(text):
        value = match.group().strip(".")
        if valid_domain(value):
            yield value


def credentials(text):
    for line in text.splitlines():
        # Check the bound before any regex; malformed megabyte lines remain linear.
        value = line.strip(" \t")
        if len(value) > 319 or ":" not in value:
            continue
        user, secret = value.split(":", 1)
        if 6 <= len(secret) <= 64 and not secret.startswith("//") and not any(c.isspace() for c in secret):
            if USER.fullmatch(user) or (len(user) <= 254 and CREDENTIAL_EMAIL.fullmatch(user)):
                yield user, secret
