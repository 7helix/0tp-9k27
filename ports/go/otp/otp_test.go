package otp

import (
	"bytes"
	"testing"
)

var (
	s1   = []byte("12345678901234567890")
	s256 = []byte("12345678901234567890123456789012")
	s512 = []byte("1234567890123456789012345678901234567890123456789012345678901234")
)

func TestHOTPRFC4226(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		got, err := HOTP(s1, uint64(i), 6, "SHA1")
		if err != nil || got != w {
			t.Fatalf("HOTP counter %d: got %q (err %v), want %q", i, got, err, w)
		}
	}
}

func TestTOTPRFC6238(t *testing.T) {
	cases := []struct {
		unix                int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}
	for _, c := range cases {
		ms := c.unix * 1000
		for _, v := range []struct {
			secret []byte
			alg    string
			want   string
		}{{s1, "SHA1", c.sha1}, {s256, "SHA256", c.sha256}, {s512, "SHA512", c.sha512}} {
			got, err := TOTP(v.secret, ms, 30, 8, v.alg)
			if err != nil || got != v.want {
				t.Fatalf("TOTP %s t=%d: got %q (err %v), want %q", v.alg, c.unix, got, err, v.want)
			}
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	const now = int64(1_700_000_000_000)
	code, _ := TOTP(s1, now, 30, 6, "SHA1")
	ok, err := VerifyTOTP(s1, code, now+30_000, 30, 1, 6, "SHA1", -1)
	if err != nil || !ok.Valid || ok.Delta != -1 {
		t.Fatalf("one step late should verify with delta -1, got %+v err %v", ok, err)
	}
	if r, _ := VerifyTOTP(s1, code, now+90_000, 30, 1, 6, "SHA1", -1); r.Valid {
		t.Fatalf("a code 3 steps old must not verify")
	}
	if r, _ := VerifyTOTP(s1, code, now, 30, 1, 6, "SHA1", ok.Counter); r.Valid || r.Reason != "replayed" {
		t.Fatalf("replay must be rejected, got %+v", r)
	}
	if r, _ := VerifyTOTP(s1, code, now, 30, 0, 6, "SHA1", -1); !r.Valid || r.Delta != 0 {
		t.Fatalf("window 0 should verify with delta 0, got %+v", r)
	}
}

func TestBase32(t *testing.T) {
	if got := Base32Encode([]byte("foobar")); got != "MZXW6YTBOI" {
		t.Fatalf("RFC 4648 vector: got %q", got)
	}
	raw := []byte{0, 1, 2, 250, 255, 7, 8, 9, 10, 11, 12}
	back, err := Base32Decode(Base32Encode(raw))
	if err != nil || !bytes.Equal(back, raw) {
		t.Fatalf("roundtrip failed: %v %v", back, err)
	}
	if b, err := Base32Decode("mzxw 6ytb-oi=="); err != nil || string(b) != "foobar" {
		t.Fatalf("lenient decode failed: %q %v", b, err)
	}
	if _, err := Base32Decode("abc!"); err == nil {
		t.Fatalf("garbage must be rejected")
	}
}

func TestValidation(t *testing.T) {
	if _, err := HOTP(s1, 0, 5, "SHA1"); err == nil {
		t.Fatal("digits < 6 must fail")
	}
	if _, err := HOTP(s1, 0, 11, "SHA1"); err == nil {
		t.Fatal("digits > 10 must fail")
	}
	if _, err := HOTP(s1, 0, 6, "MD5"); err == nil {
		t.Fatal("unsupported algorithm must fail")
	}
	if _, err := TOTP(s1, 1000, 0, 6, "SHA1"); err == nil {
		t.Fatal("step 0 must fail")
	}
	if !SafeEqual("abc", "abc") || SafeEqual("abc", "abd") || SafeEqual("abc", "abcd") {
		t.Fatal("SafeEqual misbehaves")
	}
}
