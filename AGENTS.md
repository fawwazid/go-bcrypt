# Agent instructions

This repository is the `go-bcrypt` Go module. Keep changes within this module
unless the task explicitly spans other repositories. Preserve existing user
changes. Do not create or edit changelogs; Release Please generates them.

## Security and API

- Treat bcrypt as a legacy password-storage option; recommend Argon2id for
  non-FIPS deployments and approved PBKDF2 where FIPS is required.
- Preserve the 12–16 cost policy and reject passwords over 72 bytes without
  truncation or implicit pre-hashing.
- Fail closed in FIPS mode; do not substitute another algorithm implicitly.
- Keep `NeedsRehash` and stored-cost handling consistent with the allowed cost
  policy. Do not describe this package as independently FIPS-certified.

## Development

- Workspace mail invariant: `go-mail` caps messages at 1,000 recipients, 100
  attachments, and 25 MiB; untrusted attachment bytes use its checked API.
- Workspace MFA invariant: `ConstantTimeCompare` rejects strings longer than
  4,096 UTF-8 bytes before allocating byte slices.

- Target the Go version in `go.mod`; format Go changes with `gofmt`.
- Keep `README.md` and `SECURITY.md` aligned with password limits and policy.
- Remove only clearly unused internal code; preserve exported APIs unless a
  breaking change is explicitly requested.
- Add or update regression tests for every code change and run the affected
  module's complete test suite before finishing. Run `go vet ./...` as well.
- Review password-storage changes against OWASP guidance and the package's
  FIPS policy; preserve the 72-byte limit and fail-closed behavior.
- For every workspace code, test, or security-policy change, review and update
  all eight module-level `AGENTS.md` files in the same change set so their
  constraints and test-coverage notes stay aligned. Keep updates concise; this
  is not a changelog.

## Test coverage notes

- `bcrypt_test.go` covers invalid `NeedsRehash` target costs as well as valid
  upgrade and no-upgrade cases.

## Release workflow

- Use Conventional Commit pull request titles so squash merges produce the
  intended SemVer bump: `fix:` for patch, `feat:` for minor, and `!` or
  `BREAKING CHANGE:` for major. Use `fix(security):` for security fixes;
  `security:` alone does not bump a version.
- `docs:`, `test:`, `chore:`, and `ci:` do not trigger a release. Release
  Please opens or updates a release pull request; merge that generated PR to
  create the version tag and GitHub release.
- Never create or edit changelogs manually; Release Please generates them.
- Keep the temporary `last-release-sha` at the v2 preparation commit during this rollout: the existing v2.0.0 tag is not on `main` history. After the first generated v2.0.1 release PR is merged and tagged, remove this fixed marker in a chore PR so later releases track the latest tag automatically.