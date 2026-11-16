# certval-yubikey

YubiKey PIV credentials for [certval-cms](https://github.com/carl-wallace/certval-cms). The keys in a
YubiKey's PIV slots sign CMS SignedData and decrypt CMS EnvelopedData, each identified by the
certificate in its slot.

```rust
use certval_cms::CmsEnvironment;
use certval_yubikey::{YubiKeyCard, YubiKeyIdentities};
use std::sync::Arc;

let card = Arc::new(YubiKeyCard::open(None, b"123456")?);
let identities = YubiKeyIdentities::new(card);

let mut env = CmsEnvironment::new();
env.add_recipient_credential_source(identities.clone());
env.add_signing_credential_source(identities);
```

`YubiKeyCard::open` takes a serial number to choose among several attached cards, or `None` for the
only one. It verifies the PIN and reads the certificate in each key slot; a slot with no
certificate, or one for a key this crate does not use, is passed over.

## What the card does

| Key | Signing | Decryption |
|---|---|---|
| RSA 2048, 3072, 4096 | PKCS #1 v1.5 with SHA-224, -256, -384 or -512: the encoding is built on the host, the RSA operation is the card's | key transport with PKCS #1 v1.5 padding: the card decrypts, certval-cms's `unpad_pkcs1v15` removes the padding |
| EC on P-256, P-384 | ECDSA, the digest cut to the order's length when it is longer | key agreement: the card performs the ECDH, certval-cms's `cek_from_ecdh_secret` the KDF and key unwrap |

RSASSA-PSS, RSAES-OAEP and every other algorithm are declined with `Error::Unrecognized`, so another
credential, or software, can answer.

## Which slots

Each PIV slot has a role, and the credential sources follow it rather than the key usage a
certificate asserts:

| Slot | Role | Used for |
|---|---|---|
| 9C Digital Signature | signing documents and messages | signing SignedData |
| 9D Key Management, retired 82 to 95 | the current and earlier encryption keys | decrypting EnvelopedData |
| 9A PIV Authentication, 9E Card Authentication | authentication | neither |

## The PIN

The PIN is verified when the card is opened, so a wrong one fails there, and again immediately
before every key operation, holding the card in between. A slot whose PIN policy is "always" refuses
an operation unless the PIN was verified by the command just before it; verifying each time
satisfies that whatever the slot's policy.

## Status

Not published. The `yubikey` crate is taken from its repository at the commit that moved it to
`rsa` 0.10.0: the released 0.9.0-rc.0 asks `rsa` for a feature its 0.10.0 release no longer has, so
it cannot be built beside certval-cms. Publication waits for a `yubikey` release with that change.

## Testing

`cargo test` covers what the host does: the PKCS #1 v1.5 encoding, the pairing of signature
algorithms with keys, and the reading of a key's algorithm from its certificate. CI has no YubiKey,
so the card operations are tested by hand against an attached one:

```sh
CERTVAL_YUBIKEY_PIN=123456 cargo test --test cms -- --nocapture
```

`tests/cms.rs` uses each key on the card with a certificate for what its slot is for. The Digital
Signature key signs SignedData with SHA-256, -384 and -512, which certval-cms's software verifies
(and for an RSA key, RSASSA-PSS must be declined); software encrypts EnvelopedData to the Key
Management and retired keys' certificates, which the card decrypts, by key transport for an RSA key
and key agreement for an EC key. Both look the card's key up by identifier through
`YubiKeyIdentities`, and neither lookup may find the authentication keys. Every certificate is
validated too: certval builds a path from it to a trust anchor in a certval-stores store, by default
the Purebred development store (`CERTVAL_YUBIKEY_STORE` names another), with revocation checking off,
and the signer's must come back validated. Nothing is written to
the card, so it needs at least one key with a certificate. `CERTVAL_YUBIKEY_SERIAL` chooses a card
when more than one is attached; without `CERTVAL_YUBIKEY_PIN` the test says it was skipped and
passes.

On Linux, building needs pcsc-lite's development files (`libpcsclite-dev` on Debian and Ubuntu,
`pcsc-lite-devel` on Fedora and RHEL); macOS and Windows have PC/SC built in.

## License

Apache-2.0 OR MIT.
