package gobcrypt

import (
	"crypto/sha256"
	"encoding/base64"
)

// Constants for pre-hashed password lengths.
// These are the base64-encoded lengths of a 32-byte SHA-256 hash.
const (
	// stdEncodedLen is the length of base64.StdEncoding output for a 32-byte SHA-256 hash (includes padding).
	stdEncodedLen = 44

	// rawStdEncodedLen is the length of base64.RawStdEncoding output for a 32-byte SHA-256 hash (no padding).
	rawStdEncodedLen = 43
)

// PreHashPassword hashes the password with SHA-256 and then base64 encodes it.
// This ensures the password is within the 72-byte limit of bcrypt while
// providing consistent security for passwords of any length.
// Note: All passwords are reduced to 256 bits of entropy by the SHA-256 hash.
// WARNING: This function is exported for testing and migration purposes only.
// Do NOT use it directly with standard bcrypt functions; use the Generate and Compare functions instead.
func PreHashPassword(password []byte) []byte {
	// SHA-256 hash (32 bytes)
	hash := sha256.Sum256(password)
	// Base64 encode to get a printable string (44 bytes for 32-byte SHA-256 hash)
	encoded := make([]byte, stdEncodedLen)
	base64.StdEncoding.Encode(encoded, hash[:])
	return encoded
}

// PreHashPasswordLegacy returns the legacy RawStdEncoding (no padding) base64 encoding.
// Used for backward-compatible password verification with older hashes.
// WARNING: This function is exported for testing and migration purposes only.
// Do not use it directly with standard bcrypt functions; use the Compare function instead.
func PreHashPasswordLegacy(password []byte) []byte {
	hash := sha256.Sum256(password)
	encoded := make([]byte, rawStdEncodedLen)
	base64.RawStdEncoding.Encode(encoded, hash[:])
	return encoded
}
