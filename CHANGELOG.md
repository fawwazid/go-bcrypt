# Changelog

## [2.0.2](https://github.com/fawwazid/go-bcrypt/compare/v2.0.1...v2.0.2) (2026-11-08)


### Documentation

* document branch and pull request workflow ([ea36df9](https://github.com/fawwazid/go-bcrypt/commit/ea36df9c44c8b842575cfd8ad5a31a53ba8dd627))

## [2.0.1](https://github.com/fawwazid/go-bcrypt/compare/v2.0.0...v2.0.1) (2026-11-01)


### Bug Fixes

* **release:** configure semantic versioning ([#25](https://github.com/fawwazid/go-bcrypt/issues/25)) ([7ba3f78](https://github.com/fawwazid/go-bcrypt/commit/7ba3f78f12195739750ed5aa08f089c087105c18))


### Chores

* configure Google Release Please ([747cdbe](https://github.com/fawwazid/go-bcrypt/commit/747cdbea1a985aeea4417dcd9183980f96d1b91b))
* reset Release Please baseline ([d117dd0](https://github.com/fawwazid/go-bcrypt/commit/d117dd04ac297b143ea599cbcd561c8ff11039d8))
* sync agent skill setup ([ce96e6c](https://github.com/fawwazid/go-bcrypt/commit/ce96e6c827dfa1597f4705f13d55acf338eae2fc))


### Security

* enforce bcrypt rehash cost policy ([#24](https://github.com/fawwazid/go-bcrypt/issues/24)) ([7b47e27](https://github.com/fawwazid/go-bcrypt/commit/7b47e27247d0242f1ecc17191d4de857b672e02c))

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
