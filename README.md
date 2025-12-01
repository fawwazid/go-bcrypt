# Go - bcrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-bcrypt.svg)](https://pkg.go.dev/github.com/fawwazid/go-bcrypt)
[![Go Report Card](https://goreportcard.com/badge/github.com/fawwazid/go-bcrypt)](https://goreportcard.com/report/github.com/fawwazid/go-bcrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Secure Go bcrypt implementation wrapper.

This library provides a simplified and secure API for hashing and verifying passwords using `golang.org/x/crypto/bcrypt`. It enforces modern security standards by default, preventing the use of weak hashing costs.

## Features

-   **Security Best Practices**:
    -   **Minimum Cost Enforcement**: Enforces a minimum cost of 12 (returns an error for lower values), ensuring resistance against modern hardware attacks.
    -   **Default Cost**: Uses a default cost of 14, which is a reasonable balance between security and performance for modern servers.
-   **Simple API**: Provides easy-to-use `Generate`, `Compare`, `Cost`, and `NeedsRehash` functions.
-   **Standard Compatibility**: Fully compatible with standard bcrypt implementations (produces `$2a$` hashes).

## Installation

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

-   `DefaultCost` (14): Recommended cost for modern hardware.
-   `MinCost` (12): Minimum allowed cost.
-   `MaxCost` (31): Maximum allowed cost.
-   `PasswordLimit` (72): Maximum password length (bytes).

### Functions

-   `Generate(password []byte, cost int) ([]byte, error)`: Generates a bcrypt hash.
-   `Compare(hash, password []byte) error`: Compares a hash with a password.
-   `Cost(hash []byte) (int, error)`: Returns the cost of a hash.
-   `NeedsRehash(hash []byte, targetCost int) bool`: Checks if a hash needs to be updated.

## Running Tests

To run the tests, use the standard Go test command:

```bash
go test ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
