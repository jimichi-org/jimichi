package c25519

import (
	"encoding/hex"
	"testing"
)

// the vectors of the PHC reference CLI (password "password", salt "somesalt",
// 24 bytes), the same x/crypto argon2 tests itself against
func TestArgon2idKnownAnswer(t *testing.T) {
	for _, v := range []struct {
		time, memory uint32
		threads      uint8
		want         string
	}{
		{1, 64, 1, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"},
		{2, 64, 2, "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"},
		{3, 256, 2, "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b"},
		{4, 4096, 4, "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a"},
	} {
		got := argon2id([]byte("password"), []byte("somesalt"), v.time, v.memory, v.threads, 24)
		if hex.EncodeToString(got) != v.want {
			t.Fatalf("t %d m %d p %d: %x, want %s", v.time, v.memory, v.threads, got, v.want)
		}
	}
}

// RFC 9106, section 4: t = 3, 64 MiB, p = 4 is the second recommended option
func TestArgon2idCostIsTheRecommendedOne(t *testing.T) {
	if argonTime != 3 || argonMemory != 65536 || argonThreads != 4 {
		t.Fatalf("t %d, m %d KiB, p %d", argonTime, argonMemory, argonThreads)
	}
}
