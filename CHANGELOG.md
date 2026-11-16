# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [Unreleased]

Initial version: `YubiKeyCard` opens a YubiKey and verifies its PIN, and `YubiKeyIdentities` is a
certval-cms recipient and signing credential source over the keys in its PIV slots. RSA keys sign
with PKCS #1 v1.5 and decrypt key transport with PKCS #1 v1.5 padding; EC keys on P-256 and P-384
sign with ECDSA and perform key agreement. MSRV 1.89.
