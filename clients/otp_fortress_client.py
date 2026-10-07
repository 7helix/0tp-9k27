"""Zero-dependency Python client for the 0TP-F0rtr3ss HTTP API (urllib only)."""
import base64
import hashlib
import hmac as _hmac
import json
import os
import time
import urllib.request
import urllib.error


def sign_request(method, path, body, key_id, secret, now_ms=None, nonce=None):
    """HMAC request signing - byte-for-byte compatible with src/http/signed-requests.js."""
    ts = str(int(time.time() * 1000) if now_ms is None else now_ms)
    nonce = nonce or base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    canonical = "\n".join([method.upper(), path, ts, nonce, hashlib.sha256(body).hexdigest()])
    sig = base64.urlsafe_b64encode(_hmac.new(secret, canonical.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return {"x-otpf-key-id": key_id, "x-otpf-timestamp": ts, "x-otpf-nonce": nonce, "x-otpf-signature": sig}


class OtpApiError(Exception):
    def __init__(self, status, body):
        super().__init__(body.get("error", f"HTTP {status}") if isinstance(body, dict) else f"HTTP {status}")
        self.status, self.body = status, body


class OtpFortressClient:
    def __init__(self, base_url, api_key=None, timeout=5, hmac_key_id=None, hmac_secret=None):
        self.base_url, self.api_key, self.timeout = base_url.rstrip("/"), api_key, timeout
        self.hmac_key_id, self.hmac_secret = hmac_key_id, hmac_secret

    def _post(self, path, payload):
        data = json.dumps(payload, separators=(",", ":")).encode()
        auth = (sign_request("POST", path, data, self.hmac_key_id, self.hmac_secret)
                if self.hmac_secret else {"x-api-key": self.api_key})
        req = urllib.request.Request(self.base_url + path, data=data, method="POST",
                                     headers={"content-type": "application/json", **auth})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read() or b"{}")
            if e.code == 429:
                return body
            raise OtpApiError(e.code, body) from None

    def send_otp(self, user_id, channel, to):     return self._post("/otp/send", {"userId": user_id, "channel": channel, "to": to})
    def verify_otp(self, user_id, code):          return self._post("/otp/verify", {"userId": user_id, "code": code})
    def enroll_totp(self, user_id, account):      return self._post("/totp/enroll", {"userId": user_id, "account": account})
    def confirm_totp(self, user_id, code):        return self._post("/totp/confirm", {"userId": user_id, "code": code})
    def verify_totp(self, user_id, code):         return self._post("/totp/verify", {"userId": user_id, "code": code})
    def generate_backup_codes(self, user_id):     return self._post("/backup/generate", {"userId": user_id})
    def verify_backup_code(self, user_id, code):  return self._post("/backup/verify", {"userId": user_id, "code": code})
