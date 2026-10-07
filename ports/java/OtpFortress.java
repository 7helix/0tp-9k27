import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Zero-dependency Java port of the HOTP/TOTP core (RFC 4226 / 6238).
 * Single file: copy it into your project, or run it directly (Java 17+):
 *   java OtpFortress.java selftest
 *   java OtpFortress.java batch      (stdin: "totp|hotp <base32> <timeMs|counter> <digits> <SHA1|SHA256|SHA512>")
 */
public final class OtpFortress {
    private OtpFortress() {}

    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public record VerifyResult(boolean valid, long counter, int delta, String reason) {}

    public static byte[] base32Decode(String s) {
        String clean = s.toUpperCase(Locale.ROOT).replaceAll("[\\s=-]", "");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int bits = 0, value = 0;
        for (char c : clean.toCharArray()) {
            int idx = B32.indexOf(c);
            if (idx < 0) throw new IllegalArgumentException("Invalid Base32 character");
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) { out.write((value >>> (bits - 8)) & 0xFF); bits -= 8; }
            value &= (1 << bits) - 1;
        }
        return out.toByteArray();
    }

    public static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int bits = 0, value = 0;
        for (byte b : data) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) { sb.append(B32.charAt((value >>> (bits - 5)) & 31)); bits -= 5; }
            value &= (1 << bits) - 1;
        }
        if (bits > 0) sb.append(B32.charAt((value << (5 - bits)) & 31));
        return sb.toString();
    }

    private static String macName(String algorithm) {
        return switch (algorithm.toUpperCase(Locale.ROOT)) {
            case "SHA1" -> "HmacSHA1";
            case "SHA256" -> "HmacSHA256";
            case "SHA512" -> "HmacSHA512";
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        };
    }

    /** RFC 4226 HOTP. Output is always `digits` long, with leading zeros preserved. */
    public static String hotp(byte[] secret, long counter, int digits, String algorithm) {
        if (digits < 6 || digits > 10) throw new IllegalArgumentException("digits must be 6..10");
        if (counter < 0) throw new IllegalArgumentException("counter must be >= 0");
        try {
            String name = macName(algorithm);
            Mac mac = Mac.getInstance(name);
            mac.init(new SecretKeySpec(secret, name));
            byte[] h = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());
            int off = h[h.length - 1] & 0x0F;
            int bin = ((h[off] & 0x7F) << 24) | ((h[off + 1] & 0xFF) << 16) | ((h[off + 2] & 0xFF) << 8) | (h[off + 3] & 0xFF);
            long mod = 1;
            for (int i = 0; i < digits; i++) mod *= 10;
            String s = Long.toString(bin % mod);
            return "0".repeat(digits - s.length()) + s;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static long counterAt(long timeMs, long stepSeconds) {
        if (stepSeconds <= 0) throw new IllegalArgumentException("step must be positive");
        return Math.floorDiv(Math.floorDiv(timeMs, 1000L), stepSeconds);
    }

    public static String totp(byte[] secret, long timeMs, long stepSeconds, int digits, String algorithm) {
        return hotp(secret, counterAt(timeMs, stepSeconds), digits, algorithm);
    }

    /** Constant-time comparison (hashes first so lengths never leak). */
    public static boolean safeEqual(String a, String b) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return MessageDigest.isEqual(sha.digest(a.getBytes(StandardCharsets.UTF_8)), sha.digest(b.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Verify with +/- window steps of clock drift AND replay protection.
     * Persist the returned counter and pass it back as lastUsedCounter next time.
     */
    public static VerifyResult verifyTotp(byte[] secret, String code, long timeMs, long stepSeconds, int window,
                                          int digits, String algorithm, long lastUsedCounter) {
        long current = counterAt(timeMs, stepSeconds);
        VerifyResult match = null;
        boolean replay = false;
        for (int d = -window; d <= window; d++) {            // no early exit: constant work
            long c = current + d;
            boolean ok = safeEqual(hotp(secret, c, digits, algorithm), code);
            if (ok && match == null) {
                if (c <= lastUsedCounter) replay = true;
                else match = new VerifyResult(true, c, d, null);
            }
        }
        if (match != null) return match;
        return new VerifyResult(false, -1, 0, replay ? "replayed" : "invalid");
    }

    // ------------------------------------------------------------------ self test & batch CLI
    private static int failures = 0;
    private static void check(String name, Object got, Object want) {
        if (!got.equals(want)) { failures++; System.err.println("FAIL " + name + ": got " + got + ", want " + want); }
    }

    static void selfTest() {
        byte[] s1 = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        byte[] s256 = "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
        byte[] s512 = "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII);
        String[] hotpVectors = {"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"};
        for (int i = 0; i < hotpVectors.length; i++) check("HOTP " + i, hotp(s1, i, 6, "SHA1"), hotpVectors[i]);
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[][] totpVectors = {
            {"94287082", "46119246", "90693936"}, {"07081804", "68084774", "25091201"}, {"14050471", "67062674", "99943326"},
            {"89005924", "91819424", "93441116"}, {"69279037", "90698825", "38618901"}, {"65353130", "77737706", "47863826"}};
        for (int i = 0; i < times.length; i++) {
            check("TOTP SHA1 t=" + times[i], totp(s1, times[i] * 1000, 30, 8, "SHA1"), totpVectors[i][0]);
            check("TOTP SHA256 t=" + times[i], totp(s256, times[i] * 1000, 30, 8, "SHA256"), totpVectors[i][1]);
            check("TOTP SHA512 t=" + times[i], totp(s512, times[i] * 1000, 30, 8, "SHA512"), totpVectors[i][2]);
        }
        long t = 1_700_000_000_000L;
        String code = totp(s1, t, 30, 6, "SHA1");
        VerifyResult ok = verifyTotp(s1, code, t + 30_000, 30, 1, 6, "SHA1", -1);
        check("window valid", ok.valid(), true);
        check("window delta", ok.delta(), -1);
        check("too old", verifyTotp(s1, code, t + 90_000, 30, 1, 6, "SHA1", -1).valid(), false);
        check("replay", verifyTotp(s1, code, t, 30, 1, 6, "SHA1", ok.counter()).reason(), "replayed");
        check("window 0 delta is plain 0", verifyTotp(s1, code, t, 30, 0, 6, "SHA1", -1).delta(), 0);
        byte[] raw = {0, 1, 2, (byte) 250, (byte) 255, 7, 8, 9, 10, 11, 12};
        check("base32 roundtrip", java.util.Arrays.equals(base32Decode(base32Encode(raw)), raw), true);
        check("base32 RFC vector", base32Encode("foobar".getBytes(StandardCharsets.US_ASCII)), "MZXW6YTBOI");
        boolean threw = false;
        try { base32Decode("abc!"); } catch (IllegalArgumentException e) { threw = true; }
        check("base32 rejects garbage", threw, true);
        threw = false;
        try { hotp(s1, 0, 5, "SHA1"); } catch (IllegalArgumentException e) { threw = true; }
        check("digits validated", threw, true);
        if (failures > 0) { System.err.println(failures + " failure(s)"); System.exit(1); }
        System.out.println("OK java port: RFC 4226/6238 vectors + verify/replay/base32");
    }

    static void batch() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (String line; (line = in.readLine()) != null; ) {
            String[] f = line.trim().split("\\s+");
            try {
                if (f.length != 5) throw new IllegalArgumentException();
                byte[] secret = base32Decode(f[1]);
                long n = Long.parseLong(f[2]);
                int digits = Integer.parseInt(f[3]);
                String code;
                if (f[0].equals("hotp")) code = hotp(secret, n, digits, f[4]);
                else if (f[0].equals("totp")) code = totp(secret, n, 30, digits, f[4]);
                else throw new IllegalArgumentException("unknown kind");
                out.append(code).append('\n');
            } catch (RuntimeException e) {
                out.append("ERR\n");
            }
        }
        System.out.print(out);
    }

    public static void main(String[] args) throws Exception {
        String cmd = args.length == 0 ? "selftest" : args[0];
        switch (cmd) {
            case "selftest" -> selfTest();
            case "batch" -> batch();
            default -> { System.err.println("usage: OtpFortress.java selftest | batch"); System.exit(2); }
        }
    }
}
