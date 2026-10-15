// Package vault is the client container: a file of constant size with a salt
// and two areas of one shape, each holding a volume or an empty volume under a
// discarded key. The file holds no key; a volume's key derives the client's
// identity at every open.
package vault
