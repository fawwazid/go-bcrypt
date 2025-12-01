// Package gobcrypt provides a secure wrapper around golang.org/x/crypto/bcrypt.
//
// It enforces modern security standards by setting a minimum cost for password hashing
// and providing helper functions for common operations like comparing passwords and
// checking if a hash needs to be updated.
package gobcrypt

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Generate returns the bcrypt hash of the password at the given cost.
//
// It enforces a minimum cost (MinCost) to ensure security.
// Note: bcrypt has a maximum input length of `PasswordLimit` bytes (72).
// Bytes beyond this limit are ignored by the underlying algorithm. If your
// application must support longer passwords, consider pre-hashing them (for
// example with SHA-256) before calling `Generate`, or enforce a maximum length
// at the application layer.
//
// Parameters:
//   - password: The plaintext password to hash.
//   - cost: The cost factor for the bcrypt algorithm.
//
// Returns:
//   - []byte: The generated bcrypt hash.
//   - error: An error if the cost is invalid or generation fails.
func Generate(password []byte, cost int) ([]byte, error) {
	// If the provided password exceeds bcrypt's input limit, pre-hash it
	// with SHA-256 to produce a fixed-length input. This avoids silent
	// truncation by bcrypt and allows support for arbitrarily long passwords.
	if len(password) > PasswordLimit {
		password = Prehash(password)
	}
	if cost < MinCost {
		return nil, fmt.Errorf("%w: got %d", ErrCostTooLow, cost)
	}
	if cost > MaxCost {
		return nil, fmt.Errorf("%w: got %d", ErrCostTooHigh, cost)
	}

	hash, err := bcrypt.GenerateFromPassword(password, cost)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGenerateFailed, err)
	}

	return hash, nil
}

// Compare compares a bcrypt hashed password with its possible plaintext equivalent.
//
// Note: The bcrypt algorithm ignores bytes beyond `PasswordLimit` (72), so
// passwords that differ only after that byte will compare as equal. See
// `PasswordLimit` in `constants.go` for details.
//
// Parameters:
//   - hash: The bcrypt hash to compare against.
//   - password: The plaintext password to verify.
//
// Returns:
//   - error: nil on success, or an error on failure (e.g., mismatch, empty hash).
func Compare(hash, password []byte) error {
	if len(hash) == 0 {
		return ErrHashEmpty
	}
	// If the provided password is longer than bcrypt's input limit, it must
	// be pre-hashed the same way `Generate` does so comparison succeeds.
	if len(password) > PasswordLimit {
		password = Prehash(password)
	}

	err := bcrypt.CompareHashAndPassword(hash, password)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCompareFailed, err)
	}

	return nil
}

// Cost returns the hashing cost used to create the given hash.
//
// Parameters:
//   - hash: The bcrypt hash to extract the cost from.
//
// Returns:
//   - int: The cost of the hash.
//   - error: An error if the hash is invalid.
func Cost(hash []byte) (int, error) {
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	return cost, nil
}

// NeedsRehash checks if the hash needs to be regenerated.
//
// This is useful for automatically upgrading legacy hashes to newer standards
// (e.g., if the cost used is lower than the current target cost).
//
// Parameters:
//   - hash: The bcrypt hash to check.
//   - targetCost: The minimum desired cost.
//
// Returns:
//   - bool: true if the hash is invalid or its cost is lower than targetCost.
func NeedsRehash(hash []byte, targetCost int) bool {
	c, err := bcrypt.Cost(hash)
	if err != nil {
		return true
	}
	return c < targetCost
}

// Note: `Prehash` implementation moved to `prehash.go`.
