package gobcrypt

import "crypto/sha256"

// Prehash returns a SHA-256 digest of the provided password as a byte
// slice. It is used to convert passwords longer than `PasswordLimit` into a
// fixed-length input suitable for bcrypt. This function is exported so callers
// can pre-hash passwords themselves if desired (e.g., for storage/compatibility
// scenarios).
func Prehash(password []byte) []byte {
	sum := sha256.Sum256(password)
	return sum[:]
}

// needsPrehash reports whether the password should be pre-hashed before
// passing to bcrypt. It is unexported because callers should normally use
// `Prehash` directly when needed.
func needsPrehash(password []byte) bool {
	return len(password) > PasswordLimit
}
