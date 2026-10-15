package gost

import (
	"encoding/hex"
	"testing"
)

// R 50.1.111-2016, the TC26 examples of PBKDF2 with HMAC_GOSTR3411_2012_512;
// c = 16777216 is left out, as in gogost's own tests
func TestPBKDF2KnownAnswer(t *testing.T) {
	for _, v := range []struct {
		password, salt string
		iter, size     int
		want           string
	}{
		{"password", "salt", 1, 64,
			"64770af7f748c3b1c9ac831dbcfd85c26111b30a8a657ddc3056b80ca73e040d" +
				"2854fd36811f6d825cc4ab66ec0a68a490a9e5cf5156b3a2b7eecddbf9a16b47"},
		{"password", "salt", 2, 64,
			"5a585bafdfbb6e8830d6d68aa3b43ac00d2e4aebce01c9b31c2caed56f0236d4" +
				"d34b2b8fbd2c4e89d54d46f50e47d45bbac301571743119e8d3c42ba66d348de"},
		{"password", "salt", 4096, 64,
			"e52deb9a2d2aaff4e2ac9d47a41f34c20376591c67807f0477e32549dc341bc7" +
				"867c09841b6d58e29d0347c996301d55df0d34e47cf68f4e3c2cdaf1d9ab86c3"},
		{"pass\x00word", "sa\x00lt", 4096, 64,
			"50df062885b69801a3c10248eb0a27ab6e522ffeb20c991c660f001475d73a4e" +
				"167f782c18e97e92976d9c1d970831ea78ccb879f67068cdac1910740844e830"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 100,
			"b2d8f1245fc4d29274802057e4b54e0a0753aa22fc53760b301cf008679e58fe" +
				"4bee9addcae99ba2b0b20f431a9c5e50f395c89387d0945aedeca6eb4015dfc2" +
				"bd2421ee9bb71183ba882ceebfef259f33f9e27dc6178cb89dc37428cf9cc52a" +
				"2baa2d3a"},
	} {
		if v.iter > 2 && testing.Short() {
			continue
		}
		got, err := pbkdf2Streebog([]byte(v.password), []byte(v.salt), v.iter, v.size)
		if err != nil || hex.EncodeToString(got) != v.want {
			t.Fatalf("%q, %q, c %d: %x, %v\nwant %s", v.password, v.salt, v.iter, got, err, v.want)
		}
	}
}
