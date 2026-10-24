package gobcrypt

import "errors"

const (
	// DefaultCost is the default bcrypt work factor; benchmark it for the deployment.
	DefaultCost = 14

	// MinCost is the minimum allowed cost.
	MinCost = 12

	// MaxCost is the maximum allowed cost.
	// The library caps work below bcrypt's algorithmic limit of 31 to prevent
	// unexpectedly expensive generation or verification.
	MaxCost = 16

	// PasswordLimit is the maximum password length that bcrypt can process.
	// Generate and Compare reject longer passwords.
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

// ErrPasswordTooLong is returned when a password exceeds PasswordLimit bytes.
var ErrPasswordTooLong = errors.New("gobcrypt: password exceeds maximum supported length")
