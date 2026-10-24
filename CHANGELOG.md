# Changelog

## v2.0.0 — 2026-10-24

Use direct bcrypt with bounded work and no prehash representation.

### Breaking changes

- Module path is now `github.com/fawwazid/go-bcrypt/v2`. Update imports and use Go 1.27.3 or later.
- Remove Prehash and its verification path.
- Require costs 12–16 for both generation and comparison; passwords remain limited to 72 bytes.
- bcrypt hashing and verification reject FIPS mode.

### Security and maintenance

- Check stored hash work factors before expensive verification.
- Keep wrapped errors and work-factor inspection helpers.
- Remove redundant code, obsolete comments, and compatibility paths.
- Add regression tests, current README examples, security guidance, and CI for Linux and Windows.
- FIPS policy tests use the frozen Go module v1.0.0 in both approved and strict assessment modes. This library is not independently FIPS certified; consult SECURITY.md for deployment requirements.

### Install

```sh
go get github.com/fawwazid/go-bcrypt/v2@v2.0.0
```
