# Rotating the master key without downtime
1. Generate a new key: `node bin/otp-cli.js gen-key` (use the `OTP_MASTER_KEY` value).
2. Build a `KeyRing({ keys: { 1: oldKey, 2: newKey }, current: 2 })` - new writes use key 2, key 1 still decrypts.
3. Run a background migration: for each stored ciphertext, `store(ring.rotate(ct, aad))` (see `examples/09-key-rotation.js`).
4. When `ring.needsRotation(ct)` is false for every record, remove key 1 from the ring and from your secret manager.
5. Rotate the **pepper** separately: challenge codes live minutes, so simply accept both peppers for one TTL, then drop the old one.
6. Keep the audit trail: log `key.rotated` events (never log keys).

Emergency (key suspected leaked): rotate immediately and force re-enrollment of TOTP for affected users if the *ciphertexts* were also exposed.
