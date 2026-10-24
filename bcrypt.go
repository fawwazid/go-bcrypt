// Package gobcrypt enforces bounded bcrypt costs and password lengths.
package gobcrypt

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Generate hashes a password of at most PasswordLimit bytes at cost MinCost–MaxCost.
// It returns ErrFIPSUnsupported when FIPS mode is enabled.
func Generate(password []byte, cost int) ([]byte, error) {
	if err := checkNonFIPSOperation(); err != nil {
		return nil, err
	}
	if len(password) > PasswordLimit {
		return nil, fmt.Errorf("%w: got %d bytes, maximum is %d", ErrPasswordTooLong, len(password), PasswordLimit)
	}
	if cost < MinCost {
		return nil, fmt.Errorf("%w: got %d", ErrCostTooLow, cost)
	}
	if cost > MaxCost {
		return nil, fmt.Errorf("%w: got %d", ErrCostTooHigh, cost)
	}

	hash, err := bcrypt.GenerateFromPassword(password, cost)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGenerateFailed, err)
	}

	return hash, nil
}

// Compare verifies a password using the same cost and length limits as Generate.
// It returns ErrFIPSUnsupported when FIPS mode is enabled.
func Compare(hash, password []byte) error {
	if err := checkNonFIPSOperation(); err != nil {
		return err
	}
	if len(hash) == 0 {
		return ErrHashEmpty
	}
	if len(password) > PasswordLimit {
		return fmt.Errorf("%w: got %d bytes, maximum is %d", ErrPasswordTooLong, len(password), PasswordLimit)
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCompareFailed, err)
	}
	if cost < MinCost {
		return fmt.Errorf("%w: hash cost %d is below %d", ErrCostTooLow, cost, MinCost)
	}
	if cost > MaxCost {
		return fmt.Errorf("%w: hash cost %d exceeds verification limit %d", ErrCostTooHigh, cost, MaxCost)
	}

	if err := bcrypt.CompareHashAndPassword(hash, password); err != nil {
		return fmt.Errorf("%w: %w", ErrCompareFailed, err)
	}

	return nil
}

// Cost returns the encoded work factor or an error for an invalid hash.
func Cost(hash []byte) (int, error) {
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}
	return cost, nil
}

// NeedsRehash reports invalid hashes or work factors below targetCost.
func NeedsRehash(hash []byte, targetCost int) bool {
	c, err := bcrypt.Cost(hash)
	return err != nil || c < targetCost
}
