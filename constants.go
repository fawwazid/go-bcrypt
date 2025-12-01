package gobcrypt

import "errors"

const (
	// DefaultCost is the default cost for the bcrypt algorithm.
	// It is set to 14, which provides a good balance between security and performance
	// on modern hardware.
	DefaultCost = 14

	// MinCost is the minimum allowed cost.
	// Costs below this value will result in an error to prevent insecure configurations.
	MinCost = 12

	// MaxCost is the maximum allowed cost.
	// This is limited by the bcrypt algorithm itself.
	MaxCost = 31

	// PasswordLimit is the maximum password length that bcrypt can process.
	// Passwords longer than this have bytes beyond the 72nd byte ignored by standard bcrypt.
	// This is a limitation of the bcrypt algorithm.
	PasswordLimit = 72
)

// ErrCostTooLow is returned when the provided cost is below MinCost.
var ErrCostTooLow = errors.New("gobcrypt: cost is below minimum allowed cost")

// ErrCostTooHigh is returned when the provided cost is above MaxCost.
var ErrCostTooHigh = errors.New("gobcrypt: cost exceeds maximum allowed cost")

// ErrHashEmpty is returned when the provided hash is empty.
var ErrHashEmpty = errors.New("gobcrypt: hash must not be empty")

// ErrGenerateFailed is returned when the hash generation fails.
var ErrGenerateFailed = errors.New("gobcrypt: failed to generate hash")

// ErrCompareFailed is returned when the password comparison fails.
var ErrCompareFailed = errors.New("gobcrypt: password comparison failed")

// ErrInvalidHash is returned when the hash is invalid.
var ErrInvalidHash = errors.New("gobcrypt: invalid hash")
