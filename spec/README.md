# Conformance fixtures

- [apple-sample-attestation.json](apple-sample-attestation.json): the sample attestation from Apple's [Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide), retrieved 2026-10-11, with the guide's expected values. Its `notes` record where the guide's text and its data differ.
- [provenance.json](provenance.json): the source and SHA-256 hashes of the pinned root certificate and the sample attestation. `tests/Conformance/ProvenanceTest.php` checks them.

Apple publishes no sample assertion. Add a recorded device assertion here when one is available, with its App ID and client data.
