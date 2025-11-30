package gobcrypt

import (
	"crypto/sha256"
	"encoding/base64"
)

// preHashPassword hashes the password with SHA-256 and then base64 encodes it.
// This ensures the password is within the 72-byte limit of bcrypt while
// providing consistent security for passwords of any length.
// Note: All passwords are reduced to 256 bits of entropy by the SHA-256 hash.
func preHashPassword(password []byte) []byte {
	// SHA-256 hash
	hash := sha256.Sum256(password)
	// Base64 encode to get a string-like byte slice (44 bytes with padding)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(encoded, hash[:])
	return encoded
}
