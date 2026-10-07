// Command otpf is a tiny CLI used by scripts/cross-check.js to compare this port against the
// reference implementation. Usage: otpf batch   (stdin lines: totp|hotp <base32> <timeMs|counter> <digits> <ALG>)
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"example.com/otpfortress/otp"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "batch" {
		fmt.Fprintln(os.Stderr, "usage: otpf batch")
		os.Exit(2)
	}
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) != 5 {
			fmt.Fprintln(out, "ERR")
			continue
		}
		secret, errSecret := otp.Base32Decode(f[1])
		n, errN := strconv.ParseInt(f[2], 10, 64)
		digits, errD := strconv.Atoi(f[3])
		if errSecret != nil || errN != nil || errD != nil {
			fmt.Fprintln(out, "ERR")
			continue
		}
		var code string
		var err error
		switch f[0] {
		case "totp":
			code, err = otp.TOTP(secret, n, 30, digits, f[4])
		case "hotp":
			code, err = otp.HOTP(secret, uint64(n), digits, f[4])
		default:
			err = fmt.Errorf("unknown kind")
		}
		if err != nil {
			fmt.Fprintln(out, "ERR")
		} else {
			fmt.Fprintln(out, code)
		}
	}
}
