# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Verifier::verifyAttestation()` and `Verifier::verifyAssertion()`, following
  Apple's server validation steps, with the validation category and bundle
  version extensions.
- The value types `AppId`, `Environment`, and `ValidationCategory`, and the
  results `AttestedKey` and `VerifiedAssertion`.
- `VerificationException`, with a `Failure` case for each refusal.
- The pinned Apple App Attestation Root CA, with its provenance.
- Apple's sample attestation and a real iOS 27 assertion as conformance fixtures.
- `AppAttest\Testing\TestAuthority` and `TestDevice`, for tests of applications that use the verifier.
- `CategoryPolicy::only()`, `onlyOrMissing()`, and `any()` for the validation category.
- `Failure::UnsupportedPlatform` for keys whose certificate names a platform other than `iphoneos`, or carries Apple's macOS access-control blob.
