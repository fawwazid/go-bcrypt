package gobcrypt

import (
	"crypto/sha256"
	"encoding/base64"
)

// PreHashPassword hashes the password with SHA-256 and then base64 encodes it.
// This ensures the password is within the 72-byte limit of bcrypt while
// providing consistent security for passwords of any length.
// Note: All passwords are reduced to 256 bits of entropy by the SHA-256 hash.
func PreHashPassword(password []byte) []byte {
	// SHA-256 hash (32 bytes)
	hash := sha256.Sum256(password)
	// Base64 encode to get a printable string (44 bytes total)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(encoded, hash[:])
	return encoded
}

// PreHashPasswordLegacy returns the legacy RawStdEncoding (no padding) base64 encoding.
// Used for backward-compatible password verification with older hashes.
func PreHashPasswordLegacy(password []byte) []byte {
	hash := sha256.Sum256(password)
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(hash)))
	base64.RawStdEncoding.Encode(encoded, hash[:])
	return encoded
}
