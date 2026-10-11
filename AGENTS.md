# Repository guidelines

`jewei/app-attest-php` verifies Apple App Attest attestations and assertions. It is security code: keep it small, strict, and dependency-free.

## Rules

- Runtime dependencies: PHP `^8.3` and `ext-openssl` only. Ask the owner before you add a package.
- `AppAttest\Internal` is not public API. Only `src/` and `tests/Codec/` may use it (`composer test:architecture`).
- Device data fails with `VerificationException` and a `Failure`; server arguments fail with `InvalidArgumentException`. No other exception, warning, or notice may escape for any input.
- Do not change `Failure` values: applications log them.
- Do not change the pinned root or the fixtures in `spec/` without updating `spec/provenance.json` and recording the source.
- Each verification step and each certificate check has a test that breaks only that check. A defensive guard that another check always covers may stay untested; say so in a comment.

## Checks

Run before you hand off: `composer test` and `vendor/bin/pint --test`. Mutation tests and coverage need pcov or Xdebug; they run in CI, or locally in a `php:8.3-cli` container.
