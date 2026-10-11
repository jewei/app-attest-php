# Repository guidelines

`jewei/app-attest-php` verifies Apple App Attest attestations and assertions. It is security code: keep it small, strict, and dependency-free.

## Rules

- Runtime dependencies: PHP `^8.3` and `ext-openssl` only. Ask the owner before you add a package.
- `AppAttest\Internal` is not public API. Only `src/` and `tests/Codec/` may use it (`composer test:architecture`).
- Device data fails with `VerificationException` and a `Failure`; server arguments fail with `InvalidArgumentException`. No other exception, warning, or notice may escape for any input.
- Do not change `Failure` values: applications log them.
- Do not change the pinned root or the fixtures in `spec/` without updating `spec/provenance.json` and recording the source.
- Each check in `Verifier` has a test that breaks only that check.

## Checks

Run before you hand off: `composer test` and `vendor/bin/pint --test`. Mutation tests run in CI (`composer test:mutation` needs pcov or Xdebug).
