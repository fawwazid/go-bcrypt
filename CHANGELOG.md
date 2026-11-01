# Changelog

## [3.0.0](https://github.com/fawwazid/go-bcrypt/compare/v2.0.0...v3.0.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* prepare v2 security refactor ([#22](https://github.com/fawwazid/go-bcrypt/issues/22))

### Features

* add password length validation and corresponding error handling ([fec9a0a](https://github.com/fawwazid/go-bcrypt/commit/fec9a0a69e48892a57aac8a17a675cd89d89814b))
* implement pre-hashing for long passwords and update related tests ([#13](https://github.com/fawwazid/go-bcrypt/issues/13)) ([a4774ed](https://github.com/fawwazid/go-bcrypt/commit/a4774edd47a9575506c9f0ea5533e637feaab088))
* initial implementation of secure bcrypt wrapper ([8af12aa](https://github.com/fawwazid/go-bcrypt/commit/8af12aabfd93c8173c5f4f81f0102369041b94cb))
* initial implementation of secure bcrypt wrapper ([6d8d079](https://github.com/fawwazid/go-bcrypt/commit/6d8d079187b3afa06df5c5ef370af6c37dcae58a))
* initial implementation of secure bcrypt wrapper ([0c206fd](https://github.com/fawwazid/go-bcrypt/commit/0c206fdfaa8674d2ea96cdc90607466f078fe5da))
* prepare v2 security refactor ([#22](https://github.com/fawwazid/go-bcrypt/issues/22)) ([d5c90ec](https://github.com/fawwazid/go-bcrypt/commit/d5c90ece3b2a1fd1ca54078fbf227d1690341c0e))


### Bug Fixes

* harden bcrypt password handling and update dependencies ([#20](https://github.com/fawwazid/go-bcrypt/issues/20)) ([28c403c](https://github.com/fawwazid/go-bcrypt/commit/28c403c27dc8375c0efb4f16b869459ae3e1fd10))
* remove trailing space in README.md ([1d2113a](https://github.com/fawwazid/go-bcrypt/commit/1d2113afc8f7c233ccf01536f491f5100737bae2))
* update comment to clarify 72-byte boundary test ([9980a9e](https://github.com/fawwazid/go-bcrypt/commit/9980a9ed8362b49289beaeeb7109aa2fd1bee16e))

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

## v1.2.0 — 2026-10-14

- Harden bcrypt password handling and update `golang.org/x/crypto`.

## v1.1.0 — 2025-12-01

- Add password-length validation and pre-hashing support for long passwords.

## v1.0.0 — 2025-12-01

- Initial release of the secure bcrypt wrapper.
