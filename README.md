# go-bcrypt

Install: `go get github.com/fawwazid/go-bcrypt/v2@v2.0.0`.
See [v2 release notes](CHANGELOG.md) for breaking changes.

A bounded, legacy-only bcrypt wrapper for Go 1.27.3. For new password storage,
prefer Argon2id when FIPS is not required, or PBKDF2-HMAC-SHA256 when a FIPS
approved cryptographic module is required.

## Usage

```go
package main

import (
 "fmt"
 "log"
 gobcrypt "github.com/fawwazid/go-bcrypt/v2"
)

func main() {
 password := []byte("example password")
 encoded, err := gobcrypt.Generate(password, gobcrypt.DefaultCost)
 if err != nil { log.Fatal(err) }
 if err := gobcrypt.Compare(encoded, password); err != nil { log.Fatal(err) }
 cost, err := gobcrypt.Cost(encoded)
 if err != nil { log.Fatal(err) }
 fmt.Println(cost)
}
```

## API and policy

- `Generate(password, cost)`: costs 12–16; default cost 14.
- `Compare(hash, password)`: applies the same cost range before bcrypt work.
- `Cost(hash)`: inspect the encoded cost.
- `NeedsRehash(hash, targetCost)`: report invalid hashes or costs below the target.

Benchmark the cost for your deployment and increase it over time as capacity
allows. bcrypt is intended for existing systems; it is not the preferred
choice for new password storage.

Passwords over 72 bytes are rejected. Inputs are never truncated or
automatically pre-hashed. Use a password scheme supporting longer inputs if
your application needs more than 72 bytes, including long Unicode passwords.

## Semantic versioning

Releases use Semantic Versioning through Release Please. A push to `main`
opens or updates a release pull request. Merging that generated pull request
creates the version tag and GitHub release.

Use Conventional Commits in pull request titles (the squash-merge message):

- `fix: ...`, including `fix(security): ...`, creates a patch release.
- `feat: ...` creates a minor release.
- `fix!: ...`, `feat!: ...`, or a `BREAKING CHANGE:` footer creates a
  major release.
- `docs:`, `test:`, `chore:`, and `ci:` do not trigger a release.

A `security:` commit appears under Security in generated release notes, but
does not trigger a version bump by itself. Do not edit the generated changelog
manually.
## Breaking changes

`Prehash` and all pre-hash verification examples have been removed.
Comparison no longer accepts costs below 12 or above 16.
There is one bcrypt password representation and no alternate password path.

bcrypt is outside Go's validated module. `Generate` and `Compare` return
`ErrFIPSUnsupported` in FIPS mode; no algorithm substitution is performed.

See [SECURITY.md](SECURITY.md). Run `go test ./...` and `go vet ./...`.
License: [MIT](LICENSE).
