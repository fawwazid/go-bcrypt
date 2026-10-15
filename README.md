# Go - bcrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-bcrypt.svg)](https://pkg.go.dev/github.com/fawwazid/go-bcrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Secure Go bcrypt implementation wrapper.

This library provides a simplified and secure API for hashing and verifying passwords using `golang.org/x/crypto/bcrypt`. It enforces modern security standards by default, preventing the use of weak hashing costs.

## Features

- **Security Best Practices**:
  - **Minimum Cost Enforcement**: Enforces a minimum cost of 12 (returns an error for lower values), ensuring resistance against modern hardware attacks.
  - **Default Cost**: Uses a default cost of 14, which is a reasonable balance between security and performance for modern servers.
- **Simple API**: Provides easy-to-use `Generate`, `Compare`, `Cost`, and `NeedsRehash` functions.
- **Explicit Length Safety**: Rejects passwords longer than bcrypt's 72-byte input limit instead of truncating or transparently pre-hashing them.
- **Standard Compatibility**: Fully compatible with standard bcrypt implementations (produces `$2a$` hashes).

## Long Password Support

bcrypt has a maximum input length of 72 bytes. `go-bcrypt` rejects longer inputs with `ErrPasswordTooLong` in both `Generate` and `Compare`.

The limit is measured in bytes, not Unicode characters. Applications should validate the encoded password length before registration and use a generic authentication failure response during login.

Earlier versions automatically applied SHA-256 to longer passwords. That behavior was removed because transparent fast pre-hashing can create alternative password representations and password-shucking risks. `Prehash` remains deprecated only to support controlled migration of existing hashes.

For new applications that need passwords longer than 72 bytes, prefer Argon2id rather than combining a fast hash with bcrypt.

To verify an existing long-password hash created by an older release, explicitly compare its legacy digest and replace the hash with a new scheme after successful authentication:

```go
if err := gobcrypt.Compare(storedHash, gobcrypt.Prehash(password)); err != nil {
	return err
}
// Migrate this credential to Argon2id here.
```

Only use this compatibility path for records known to use the legacy prehash scheme. Store an algorithm/version identifier with password hashes so normal bcrypt and legacy-prehashed records cannot be confused.

## Installation

Requires Go 1.26 or newer.

```bash
go get github.com/fawwazid/go-bcrypt
```

## Usage

### Hashing a Password

```go
package main

import (
	"fmt"
	"log"

	gobcrypt "github.com/fawwazid/go-bcrypt"
)

func main() {
	password := []byte("my-super-secret-password")

	// Generate a hash with the default cost (14)
	hash, err := gobcrypt.Generate(password, gobcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Hashed Password: %s\n", hash)
}
```

### Verifying a Password

```go
package main

import (
	"fmt"

	gobcrypt "github.com/fawwazid/go-bcrypt"
)

func main() {
	password := []byte("my-super-secret-password")
	// In a real app, retrieve this hash from your database
	hash := []byte("$2a$14$...")

	err := gobcrypt.Compare(hash, password)
	if err != nil {
		fmt.Println("Invalid password")
	} else {
		fmt.Println("Password matches!")
	}
}
```

### Checking for Rehash (Password Upgrades)

It is good practice to check if a password needs to be rehashed (e.g., if you have increased your security standards or the original hash used a low cost).

```go
func login(password []byte, storedHash []byte) error {
    // 1. Verify password
    if err := gobcrypt.Compare(storedHash, password); err != nil {
        // Handle invalid password
        return err
    }

    // 2. Check if we need to upgrade the hash
    // If the stored hash cost is lower than DefaultCost (14), this returns true.
    if gobcrypt.NeedsRehash(storedHash, gobcrypt.DefaultCost) {
        newHash, err := gobcrypt.Generate(password, gobcrypt.DefaultCost)
        if err != nil {
            // Log the error or handle appropriately
            return err
        }
        // TODO: Save newHash to database for this user
        _ = newHash
    }
    return nil
}
```

## API Reference

### Constants

- `DefaultCost` (14): Recommended cost for modern hardware.
- `MinCost` (12): Minimum allowed cost.
- `MaxCost` (31): Maximum allowed cost.
- `PasswordLimit` (72): Maximum password length (bytes).
  - `Generate` and `Compare` return `ErrPasswordTooLong` for longer inputs.

### Functions

- `Generate(password []byte, cost int) ([]byte, error)`: Generates a bcrypt hash.
- `Compare(hash, password []byte) error`: Compares a hash with a password.
- `Cost(hash []byte) (int, error)`: Returns the cost of a hash.
- `NeedsRehash(hash []byte, targetCost int) bool`: Checks if a hash needs to be updated.
- `Prehash(password []byte) []byte`: Deprecated migration helper for hashes created by older releases.

## Security and Compliance

This package provides password hashing, not a complete authentication system. Applications are responsible for password policy, breached-password screening, rate limiting, MFA, TLS, secure storage, and generic login errors.

bcrypt is appropriate for maintaining compatible legacy bcrypt deployments. For new systems, prefer Argon2id. Environments requiring FIPS-validated cryptography should use an approved implementation and algorithm selected under their compliance program; this package does not claim NIST or FIPS certification.

## Running Tests

To run the tests, use the standard Go test command:

```bash
go test ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
