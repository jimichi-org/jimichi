package crypto

import "errors"

const PasswordMax = 256

var ErrBadPassword = errors.New("crypto: bad password")

// 1 to PasswordMax bytes taken as typed, without normalisation, and no NUL, CR
// or LF: one rule for the command line, the admin port and the provider, so a
// line ending never becomes part of a password on one path only
func ValidPassword(p []byte) bool {
	if len(p) == 0 || len(p) > PasswordMax {
		return false
	}
	for _, c := range p {
		if c == 0x00 || c == '\r' || c == '\n' {
			return false
		}
	}
	return true
}
