package crypto_test

import (
	"strings"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

// one rule for every path a password comes by: 1 to 256 bytes as typed, no
// NUL, CR or LF; any other byte, a non-ASCII one included, is taken
func TestValidPassword(t *testing.T) {
	for _, p := range []string{
		"a", strings.Repeat("x", jcrypto.PasswordMax), "pass word", "tab\there", "\xd0\xb6\xd1\x83\xd0\xba", "\x7f\xff",
	} {
		if !jcrypto.ValidPassword([]byte(p)) {
			t.Fatalf("%q is refused", p)
		}
	}
	for _, p := range []string{
		"", strings.Repeat("x", jcrypto.PasswordMax+1), "pass\x00word", "password\n", "password\r\n", "\rpassword",
	} {
		if jcrypto.ValidPassword([]byte(p)) {
			t.Fatalf("%q is taken", p)
		}
	}
}
