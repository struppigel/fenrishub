"""Encrypt small secrets (helpers' centralbox API keys) for storage in the database.

Fernet (AES + HMAC) with a key derived from settings.SECRET_KEY, so a database
dump alone does not reveal the secrets. If SECRET_KEY ever changes, stored
values can no longer be decrypted: `decrypt` then returns None and the helper
simply enters the key again. Never log or render the decrypted value.
"""

import base64
import hashlib

from django.conf import settings

_LABEL = b'fenrishub:secret-box:v1:'


def _fernet():
    from cryptography.fernet import Fernet

    digest = hashlib.sha256(_LABEL + settings.SECRET_KEY.encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(text):
    """The encrypted form of `text` (a str), safe to store."""
    return _fernet().encrypt(text.encode('utf-8')).decode('ascii')


def decrypt(token):
    """The original text, or None when `token` is empty, tampered with or was
    encrypted under another SECRET_KEY. Never raises."""
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode('ascii')).decode('utf-8')
    except Exception:
        return None
