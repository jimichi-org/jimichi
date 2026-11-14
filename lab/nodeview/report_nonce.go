package nodeview

import (
	"crypto/rand"
	"encoding/hex"
)

func reportNonce() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
