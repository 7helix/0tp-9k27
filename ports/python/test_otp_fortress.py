import unittest
import otp_fortress as o

S1 = b"12345678901234567890"
S256 = b"12345678901234567890123456789012"
S512 = b"1234567890123456789012345678901234567890123456789012345678901234"


class Vectors(unittest.TestCase):
    def test_hotp_rfc4226(self):
        exp = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        for i, e in enumerate(exp):
            self.assertEqual(o.hotp(S1, i), e)

    def test_totp_rfc6238(self):
        rows = [(59, "94287082", "46119246", "90693936"), (1111111109, "07081804", "68084774", "25091201"),
                (1111111111, "14050471", "67062674", "99943326"), (1234567890, "89005924", "91819424", "93441116"),
                (2000000000, "69279037", "90698825", "38618901"), (20000000000, "65353130", "77737706", "47863826")]
        for t, a, b, c in rows:
            self.assertEqual(o.totp(S1, t, digits=8, algorithm="SHA1"), a)
            self.assertEqual(o.totp(S256, t, digits=8, algorithm="SHA256"), b)
            self.assertEqual(o.totp(S512, t, digits=8, algorithm="SHA512"), c)

    def test_verify_window_and_replay(self):
        t = 1_700_000_000
        code = o.totp(S1, t)
        ok, ctr = o.verify_totp(S1, code, t + 30)
        self.assertTrue(ok)
        self.assertFalse(o.verify_totp(S1, code, t + 90)[0])
        self.assertFalse(o.verify_totp(S1, code, t, last_used_counter=ctr)[0])

    def test_base32_roundtrip(self):
        s = o.new_secret()
        self.assertEqual(o.base32_decode(o.base32_encode(s)), s)

    def test_cross_language_agreement_with_js_reference(self):
        # Same secret + time as tests/core.test.js's RFC row: JS and Python must agree.
        self.assertEqual(o.totp(S1, 59, digits=8), "94287082")


if __name__ == "__main__":
    unittest.main()
