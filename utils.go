package gobcrypt

import (
	"crypto/sha256"
	"encoding/base64"
)

// preHashPassword hashes the password with SHA-256 and then base64 encodes it.
// This ensures the password is within the 72-byte limit of bcrypt while
// preserving the entropy of long passwords.
func preHashPassword(password []byte) []byte {
	// SHA-256 hash
	hash := sha256.Sum256(password)
	// Base64 encode to get a string-like byte slice
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(hash)))
	base64.RawStdEncoding.Encode(encoded, hash[:])
	return encoded
}
