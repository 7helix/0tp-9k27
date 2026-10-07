// Package otp is a dependency-free Go port of the HOTP/TOTP core (RFC 4226 / RFC 6238):
// HOTP, TOTP (SHA1/SHA256/SHA512), Base32, constant-time verification with clock-drift window
// and replay protection. It mirrors src/core/*.js so behaviour is identical across languages
// (see scripts/cross-check.js).
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Base32Decode accepts upper/lower case and ignores spaces, dashes and '=' padding.
func Base32Decode(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	return b32.DecodeString(clean)
}

// Base32Encode returns unpadded RFC 4648 Base32.
func Base32Encode(b []byte) string { return b32.EncodeToString(b) }

func hashFor(alg string) (func() hash.Hash, error) {
	switch strings.ToUpper(alg) {
	case "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("unsupported algorithm: %s", alg)
}

// HOTP computes an RFC 4226 code. The result always has `digits` characters (leading zeros kept).
func HOTP(secret []byte, counter uint64, digits int, alg string) (string, error) {
	if digits < 6 || digits > 10 {
		return "", errors.New("digits must be 6..10")
	}
	h, err := hashFor(alg)
	if err != nil {
		return "", err
	}
	mac := hmac.New(h, secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := int(sum[len(sum)-1] & 0x0f)
	bin := uint64(sum[off]&0x7f)<<24 | uint64(sum[off+1])<<16 | uint64(sum[off+2])<<8 | uint64(sum[off+3])
	mod := uint64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod), nil
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// Counter returns the TOTP time-step counter for a Unix time in milliseconds.
func Counter(unixMillis, step int64) (int64, error) {
	if step <= 0 {
		return 0, errors.New("step must be positive")
	}
	c := floorDiv(floorDiv(unixMillis, 1000), step)
	if c < 0 {
		return 0, errors.New("time before the epoch")
	}
	return c, nil
}

// TOTP computes an RFC 6238 code for the given Unix time in milliseconds.
func TOTP(secret []byte, unixMillis, step int64, digits int, alg string) (string, error) {
	c, err := Counter(unixMillis, step)
	if err != nil {
		return "", err
	}
	return HOTP(secret, uint64(c), digits, alg)
}

// SafeEqual compares strings in constant time (hashing first so lengths never leak).
func SafeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// VerifyResult is the outcome of VerifyTOTP. Persist Counter and pass it back as lastUsedCounter.
type VerifyResult struct {
	Valid   bool
	Counter int64
	Delta   int
	Reason  string // "", "invalid" or "replayed"
}

// VerifyTOTP checks a code with +/- window steps of drift and rejects replays of already-used counters.
// All candidates are always evaluated (no early exit).
func VerifyTOTP(secret []byte, code string, unixMillis, step int64, window, digits int, alg string, lastUsedCounter int64) (VerifyResult, error) {
	current, err := Counter(unixMillis, step)
	if err != nil {
		return VerifyResult{}, err
	}
	var match *VerifyResult
	replay := false
	for d := -window; d <= window; d++ {
		c := current + int64(d)
		if c < 0 {
			continue
		}
		cand, err := HOTP(secret, uint64(c), digits, alg)
		if err != nil {
			return VerifyResult{}, err
		}
		if SafeEqual(cand, code) && match == nil {
			if c <= lastUsedCounter {
				replay = true
			} else {
				match = &VerifyResult{Valid: true, Counter: c, Delta: d}
			}
		}
	}
	if match != nil {
		return *match, nil
	}
	if replay {
		return VerifyResult{Reason: "replayed"}, nil
	}
	return VerifyResult{Reason: "invalid"}, nil
}
