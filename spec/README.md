# Conformance fixtures

- [apple-sample-attestation.json](apple-sample-attestation.json): the sample attestation from Apple's [Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide), retrieved 2026-10-11, with the guide's expected values. Its `notes` record where the guide's text and its data differ.
- [third-party/block-buzz-ios27-assertion.json](third-party/block-buzz-ios27-assertion.json): a real iOS 27 assertion with the validation category and bundle version extensions, from [block/buzz pull request #8020](https://github.com/block/buzz/pull/8020) (Apache-2.0; see [third-party/LICENSE-block-buzz](third-party/LICENSE-block-buzz)). It has the app's raw public key point, client data, and counters, but no attestation.
- [provenance.json](provenance.json): the source and SHA-256 hashes of the pinned root certificate (the PEM file and the certificate), Apple's sample attestation (the decoded attestation object), and the third-party fixture (the file). `tests/Conformance/ProvenanceTest.php` checks them.

Apple publishes no sample assertion. Add an attestation and assertion recorded from a device that you control when one is available, with its App ID and client data.
