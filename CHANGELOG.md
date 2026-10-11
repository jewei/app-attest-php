# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Verifier::verifyAttestation()` and `Verifier::verifyAssertion()`, following
  Apple's server validation steps, with the validation category and bundle
  version extensions.
- The pinned Apple App Attestation Root CA, with its provenance.
- Apple's sample attestation as a conformance fixture.
