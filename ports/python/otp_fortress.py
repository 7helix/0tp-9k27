"""Pure-Python (stdlib only) HOTP / TOTP reference port - verified against RFC 4226 / 6238 vectors."""
import base64
import hashlib
import hmac
import secrets
import struct
import time

_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def base32_decode(s: str) -> bytes:
    s = s.upper().replace(" ", "").replace("-", "").rstrip("=")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def base32_encode(b: bytes) -> str:
    return base64.b32encode(b).decode().rstrip("=")


def new_secret(n: int = 20) -> bytes:
    return secrets.token_bytes(n)


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    if not 6 <= digits <= 10:
        raise ValueError("digits must be 6..10")
    h = hmac.new(secret, struct.pack(">Q", counter), _ALGOS[algorithm.upper()]).digest()
    off = h[-1] & 0x0F
    code = struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


def totp(secret: bytes, at: float | None = None, step: int = 30, digits: int = 6, algorithm: str = "SHA1") -> str:
    at = time.time() if at is None else at
    return hotp(secret, int(at) // step, digits, algorithm)


def verify_totp(secret: bytes, code: str, at: float | None = None, step: int = 30, window: int = 1,
                digits: int = 6, algorithm: str = "SHA1", last_used_counter: int = -1):
    """Returns (valid, counter). Persist `counter` and pass it back as last_used_counter to block replays."""
    at = time.time() if at is None else at
    current = int(at) // step
    match = None
    for d in range(-window, window + 1):  # no early exit
        c = current + d
        if hmac.compare_digest(hotp(secret, c, digits, algorithm), str(code)) and c > last_used_counter and match is None:
            match = c
    return (match is not None, match)
