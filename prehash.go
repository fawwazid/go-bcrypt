package gobcrypt

import "crypto/sha256"

// Prehash returns the SHA-256 digest of password. It is retained only to help
// applications verify and migrate hashes created by versions that performed
// automatic pre-hashing.
//
// Do not use this function when creating new bcrypt hashes. A fast, unkeyed
// pre-hash can introduce alternative password representations and password-
// shucking risks unless the complete scheme is explicitly versioned.
//
// Deprecated: reject passwords longer than PasswordLimit or migrate to a
// password hashing algorithm designed for long inputs, such as Argon2id.
func Prehash(password []byte) []byte {
	sum := sha256.Sum256(password)
	return sum[:]
}
