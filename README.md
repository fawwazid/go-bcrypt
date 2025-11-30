# Go - Bcrypt

A secure wrapper for Go's bcrypt implementation.

This library provides a simplified API for hashing and verifying passwords using bcrypt, with built-in enforcement of modern security standards.

## Features

-   **Security Best Practices**:
    -   **Minimum Cost Enforcement**: Enforces a minimum cost of 12 (defaulting to 14), ensuring resistance against modern hardware attacks.
    -   **Long Password Support**: Automatically handles passwords longer than 72 bytes by pre-hashing them with SHA-256. This bypasses the native bcrypt length limitation while maintaining full entropy.
-   **Modern Versioning**: Automatically upgrades the legacy `$2a$` prefix to `$2b$` to signal a secure, bug-free implementation.
-   **Simple API**: Provides easy-to-use `Generate`, `Compare`, `Cost`, and `NeedsRehash` functions.

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
	password := []byte("my-super-secret-password-that-is-very-long")

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
	password := []byte("my-super-secret-password-that-is-very-long")
	hash := []byte("$2b$14$...") // Your stored hash

	err := gobcrypt.Compare(hash, password)
	if err != nil {
		fmt.Println("Invalid password")
	} else {
		fmt.Println("Password matches!")
	}
}
```

### Checking for Rehash

It is good practice to check if a password needs to be rehashed (e.g., if you have increased your security standards or the original hash used a low cost).

```go
func login(password []byte, storedHash []byte) {
    // 1. Verify password
    if err := gobcrypt.Compare(storedHash, password); err != nil {
        // Handle invalid password
        return
    }

    // 2. Check if we need to upgrade the hash
    if gobcrypt.NeedsRehash(storedHash, gobcrypt.DefaultCost) {
        newHash, _ := gobcrypt.Generate(password, gobcrypt.DefaultCost)
        // Save newHash to database...
    }
}
```

## Security Details

### Why Pre-hashing?
Bcrypt has a maximum password length of 72 bytes. Passwords longer than this are truncated, which reduces security for long passphrases. This library pre-hashes all passwords using SHA-256 (and base64 encoding) before passing them to bcrypt. This allows for passwords of arbitrary length without losing entropy.

### Why `$2b$`?
Standard bcrypt implementations use version prefixes to indicate the algorithm variant.
-   `$2a$`: The standard for many years, but had a bug in some implementations regarding long passwords.
-   `$2b$`: The modern standard that fixes these issues.

This library outputs `$2b$` hashes to ensure compatibility with the latest security best practices.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
