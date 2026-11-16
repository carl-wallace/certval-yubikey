//! YubiKey PIV credentials for [`certval_cms`].
//!
//! The keys in a YubiKey's PIV slots sign CMS SignedData and decrypt CMS EnvelopedData, each
//! identified by the certificate in its slot. [`YubiKeyCard`] opens a card and verifies its PIN;
//! [`YubiKeyIdentities`] is a source of both recipient and signing credentials over the keys it
//! holds, registered on a [`CmsEnvironment`]:
//!
//! ```no_run
//! use certval_cms::CmsEnvironment;
//! use certval_yubikey::{YubiKeyCard, YubiKeyIdentities};
//! use std::sync::Arc;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let card = Arc::new(YubiKeyCard::open(None, b"123456")?);
//! let identities = YubiKeyIdentities::new(card);
//!
//! let mut env = CmsEnvironment::new();
//! env.add_recipient_credential_source(identities.clone());
//! env.add_signing_credential_source(identities);
//! # Ok(())
//! # }
//! ```
//!
//! # What the card does
//!
//! - **RSA** (2048, 3072 and 4096 bits): PKCS #1 v1.5 signatures with SHA-224, -256, -384 or -512,
//!   the encoding built here and the RSA operation on the card; and key transport with PKCS #1 v1.5
//!   padding, the card decrypting and [`unpad_pkcs1v15`] removing the padding. RSASSA-PSS and
//!   RSAES-OAEP are declined.
//! - **EC** on P-256 and P-384: ECDSA signatures, and key agreement, the card performing the ECDH
//!   and [`cek_from_ecdh_secret`] the rest.
//!
//! Anything else is declined with [`Error::Unrecognized`], so another credential, or software, can
//! answer.
//!
//! # Which slots
//!
//! Each PIV slot has a role (NIST SP 800-73), and the sources follow it rather than the key usage
//! a certificate asserts:
//!
//! - the Digital Signature key (9C) signs SignedData;
//! - the Key Management key (9D) and the retired key management keys (82 to 95), which a card
//!   keeps so that messages encrypted to earlier keys can still be read, decrypt EnvelopedData;
//! - the PIV Authentication (9A) and Card Authentication (9E) keys are for authentication, and are
//!   offered for neither, though their certificates may assert digitalSignature or
//!   keyEncipherment.
//!
//! # The PIN
//!
//! The PIN is verified when the card is opened, so a wrong one fails there rather than at the first
//! operation, and again immediately before every key operation. A slot whose PIN policy is
//! "always" refuses an operation unless the PIN was verified by the command just before it, and
//! verifying each time is what satisfies that whatever the slot's policy.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

use std::sync::{Arc, Mutex};

use certval_cms::{
    cek_from_ecdh_secret, recipient_matches, unpad_pkcs1v15, CmsEnvironment, Error,
    KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, RecipientCredential,
    RecipientCredentialSource, Result, SharedRecipientCredential, SharedSigningCredential,
    SigningCredential, SigningCredentialLookup, SigningCredentialSource,
};
use cms::enveloped_data::RecipientIdentifier;
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
    ID_EC_PUBLIC_KEY, ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION, SECP_256_R_1,
    SECP_384_R_1, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, UintRef};
use der::{Any, Decode, Encode, Sequence};
use log::error;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::{Serial, YubiKey};
use zeroize::Zeroizing;

/// An open YubiKey, its PIN, and the keys in its PIV slots that have a certificate.
pub struct YubiKeyCard {
    yubikey: Mutex<YubiKey>,
    pin: Zeroizing<Vec<u8>>,
    keys: Vec<SlotKey>,
}

/// A key in a PIV slot, known by the certificate in the same slot.
struct SlotKey {
    slot: SlotId,
    algorithm: AlgorithmId,
    certificate: Certificate,
}

impl YubiKeyCard {
    /// Opens the YubiKey with `serial`, or with `None`, the only one attached, verifies `pin`, and
    /// reads the certificate in each key slot. A slot with no certificate, or with a certificate
    /// for a key this crate does not use, is passed over.
    ///
    /// The key slots are the four PIV slots and the twenty retired ones. The attestation slot is
    /// left out, and so are the yubikey crate's management slots, which hold no key; it maps them
    /// onto other slots' certificate objects (the PIN's is 9D's), so reading one returns a
    /// certificate that belongs to another slot.
    pub fn open(serial: Option<u32>, pin: &[u8]) -> yubikey::Result<Self> {
        let mut yubikey = match serial {
            Some(serial) => YubiKey::open_by_serial(Serial(serial))?,
            None => YubiKey::open()?,
        };
        yubikey.verify_pin(pin)?;
        let keys = piv::SLOTS
            .into_iter()
            .filter(|slot| !matches!(slot, SlotId::Attestation | SlotId::Management(_)))
            .filter_map(|slot| {
                let certificate = yubikey::Certificate::read(&mut yubikey, slot).ok()?.cert;
                let algorithm =
                    key_algorithm(certificate.tbs_certificate().subject_public_key_info())?;
                Some(SlotKey {
                    slot,
                    algorithm,
                    certificate,
                })
            })
            .collect();
        Ok(Self {
            yubikey: Mutex::new(yubikey),
            pin: Zeroizing::new(pin.to_vec()),
            keys,
        })
    }

    /// The serial number of the card.
    pub fn serial(&self) -> Option<u32> {
        self.yubikey.lock().ok().map(|yubikey| yubikey.serial().0)
    }

    /// The certificates of the keys found on the card, with the slot each key is in.
    pub fn certificates(&self) -> impl Iterator<Item = (SlotId, &Certificate)> {
        self.keys.iter().map(|key| (key.slot, &key.certificate))
    }

    /// Verifies the PIN and then performs `operation`, holding the card throughout, so that nothing
    /// is sent to it between the two. `what` names the operation in an error.
    fn perform<T>(
        &self,
        what: &str,
        operation: impl FnOnce(&mut YubiKey) -> yubikey::Result<T>,
    ) -> Result<T> {
        let mut yubikey = self
            .yubikey
            .lock()
            .map_err(|_| Error::Crypto(String::from("the YubiKey is unavailable")))?;
        yubikey.verify_pin(&self.pin).map_err(|e| {
            error!("the YubiKey refused the PIN: {e}");
            Error::Crypto(String::from("the YubiKey refused the PIN"))
        })?;
        operation(&mut yubikey).map_err(|e| {
            error!("the YubiKey could not {what}: {e}");
            Error::Crypto(format!("the YubiKey could not {what}"))
        })
    }
}

/// The certificates on a YubiKey, each with the key in the same slot, as a source of both
/// recipient and signing credentials: the Digital Signature key signs, and the Key Management key
/// and the retired key management keys decrypt.
#[derive(Clone)]
pub struct YubiKeyIdentities {
    card: Arc<YubiKeyCard>,
}

impl YubiKeyIdentities {
    /// A source over the keys on `card`.
    pub fn new(card: Arc<YubiKeyCard>) -> Self {
        Self { card }
    }

    fn credential(&self, index: usize) -> YubiKeyCredential {
        YubiKeyCredential {
            card: self.card.clone(),
            index,
        }
    }
}

impl RecipientCredentialSource for YubiKeyIdentities {
    fn find_recipient_credential(
        &self,
        _env: &CmsEnvironment,
        rid: &RecipientIdentifier,
    ) -> Result<Option<SharedRecipientCredential>> {
        Ok(self
            .card
            .keys
            .iter()
            .position(|key| decrypts(key.slot) && recipient_matches(rid, &key.certificate))
            .map(|index| Arc::new(self.credential(index)) as SharedRecipientCredential))
    }
}

impl SigningCredentialSource for YubiKeyIdentities {
    fn find_signing_credentials(
        &self,
        _env: &CmsEnvironment,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<Vec<SharedSigningCredential>> {
        Ok(self
            .card
            .keys
            .iter()
            .enumerate()
            .filter(|(_, key)| signs(key.slot) && lookup.matches(&key.certificate))
            .map(|(index, _)| Arc::new(self.credential(index)) as SharedSigningCredential)
            .collect())
    }
}

/// Whether the key in `slot` signs SignedData: the Digital Signature key alone.
fn signs(slot: SlotId) -> bool {
    matches!(slot, SlotId::Signature)
}

/// Whether the key in `slot` decrypts EnvelopedData: the Key Management key and the retired key
/// management keys.
fn decrypts(slot: SlotId) -> bool {
    matches!(slot, SlotId::KeyManagement | SlotId::Retired(_))
}

/// A key on a YubiKey with its certificate: a recipient credential for an RSA or EC key, and a
/// signing credential for either.
pub struct YubiKeyCredential {
    card: Arc<YubiKeyCard>,
    index: usize,
}

impl YubiKeyCredential {
    fn key(&self) -> &SlotKey {
        &self.card.keys[self.index]
    }
}

impl RecipientCredential for YubiKeyCredential {
    fn certificate(&self) -> &Certificate {
        &self.key().certificate
    }

    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.key();
        // The card decrypts without removing any padding, and only PKCS #1 v1.5's is removed here.
        if alg != KeyTransportAlgorithm::RsaPkcs1v15 {
            return Err(Error::Unrecognized);
        }
        let k = modulus_len(key.algorithm).ok_or(Error::Unrecognized)?;
        if encrypted_key.len() != k {
            return Err(Error::Crypto(String::from("key transport failed")));
        }
        let em = self.card.perform("decrypt a key", |yubikey| {
            piv::decrypt_data(yubikey, encrypted_key, key.algorithm, key.slot)
        })?;
        unpad_pkcs1v15(&em, k)
    }

    fn decrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.key();
        if field_len(key.algorithm).is_none() {
            return Err(Error::Unrecognized);
        }
        // The originator's key must be on the recipient's curve; the card checks the point.
        if key_algorithm(originator) != Some(key.algorithm) {
            return Err(Error::InvalidInput(String::from(
                "the originator's key is not on the recipient's curve",
            )));
        }
        let point = originator.subject_public_key.as_bytes().ok_or_else(|| {
            Error::InvalidInput(String::from("the originator's key is malformed"))
        })?;
        let z = self.card.perform("agree a key", |yubikey| {
            piv::decrypt_data(yubikey, point, key.algorithm, key.slot)
        })?;
        let z = Zeroizing::new(z.to_vec());
        cek_from_ecdh_secret(alg, wrap, &z, ukm, encrypted_key)
    }
}

impl SigningCredential for YubiKeyCredential {
    fn certificate(&self) -> &Certificate {
        &self.key().certificate
    }

    fn sign_digest(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self.key();
        let input = signature_input(key.algorithm, alg, digest).ok_or(Error::Unrecognized)?;
        let signature = self.card.perform("sign", |yubikey| {
            piv::sign_data(yubikey, &input, key.algorithm, key.slot)
        })?;
        Ok(signature.to_vec())
    }
}

/// What the card signs for a `digest` under the signature algorithm `alg`, with a key of
/// `algorithm`: the EMSA-PKCS1-v1_5 encoding (RFC 8017, section 9.2) of the digest for an RSA key,
/// and for an EC key the digest itself, cut to the length of the curve's order as ECDSA does with
/// a longer one (FIPS 186-5, section 6.4.1). `None` when the algorithm is not one this crate
/// performs with that key, or the digest is not its hash's length.
fn signature_input(
    algorithm: AlgorithmId,
    alg: &AlgorithmIdentifierOwned,
    digest: &[u8],
) -> Option<Vec<u8>> {
    if let Some(k) = modulus_len(algorithm) {
        let hash = match alg.oid {
            SHA_224_WITH_RSA_ENCRYPTION => ID_SHA_224,
            SHA_256_WITH_RSA_ENCRYPTION => ID_SHA_256,
            SHA_384_WITH_RSA_ENCRYPTION => ID_SHA_384,
            SHA_512_WITH_RSA_ENCRYPTION => ID_SHA_512,
            _ => return None,
        };
        if digest.len() != hash_len(hash)? {
            return None;
        }
        return emsa_pkcs1_v1_5(hash, digest, k);
    }
    let field_len = field_len(algorithm)?;
    let hash = match alg.oid {
        ECDSA_WITH_SHA_224 => ID_SHA_224,
        ECDSA_WITH_SHA_256 => ID_SHA_256,
        ECDSA_WITH_SHA_384 => ID_SHA_384,
        ECDSA_WITH_SHA_512 => ID_SHA_512,
        _ => return None,
    };
    if digest.len() != hash_len(hash)? {
        return None;
    }
    Some(digest[..digest.len().min(field_len)].to_vec())
}

/// `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`
#[derive(Sequence)]
struct DigestInfo {
    algorithm: AlgorithmIdentifierOwned,
    digest: OctetString,
}

/// EMSA-PKCS1-v1_5 (RFC 8017, section 9.2): `0x00 0x01 PS 0x00 DigestInfo`, `PS` being octets of
/// `0xff` that make the encoding `k` octets long.
fn emsa_pkcs1_v1_5(hash: ObjectIdentifier, digest: &[u8], k: usize) -> Option<Vec<u8>> {
    let t = DigestInfo {
        algorithm: AlgorithmIdentifierOwned {
            oid: hash,
            // RFC 4055 has the parameters present and NULL for these hash algorithms.
            parameters: Some(Any::null()),
        },
        digest: OctetString::new(digest).ok()?,
    }
    .to_der()
    .ok()?;
    // At least eight octets of padding (RFC 8017, section 9.2, step 3).
    let padding = k.checked_sub(t.len() + 3).filter(|len| *len >= 8)?;
    let mut em = Vec::with_capacity(k);
    em.extend_from_slice(&[0x00, 0x01]);
    em.resize(2 + padding, 0xff);
    em.push(0x00);
    em.extend_from_slice(&t);
    Some(em)
}

/// The length in octets of a digest of the hash algorithm `hash`.
fn hash_len(hash: ObjectIdentifier) -> Option<usize> {
    match hash {
        ID_SHA_224 => Some(28),
        ID_SHA_256 => Some(32),
        ID_SHA_384 => Some(48),
        ID_SHA_512 => Some(64),
        _ => None,
    }
}

/// The length in octets of an RSA key's modulus, `None` for a key that is not RSA.
fn modulus_len(algorithm: AlgorithmId) -> Option<usize> {
    match algorithm {
        AlgorithmId::Rsa1024 => Some(128),
        AlgorithmId::Rsa2048 => Some(256),
        AlgorithmId::Rsa3072 => Some(384),
        AlgorithmId::Rsa4096 => Some(512),
        _ => None,
    }
}

/// The length in octets of an EC key's field elements, `None` for a key that is not EC.
fn field_len(algorithm: AlgorithmId) -> Option<usize> {
    match algorithm {
        AlgorithmId::EccP256 => Some(32),
        AlgorithmId::EccP384 => Some(48),
        _ => None,
    }
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

/// The card's algorithm for the key `spki` holds: RSA by the length of its modulus, EC by its
/// named curve. `None` for any other key.
fn key_algorithm(spki: &SubjectPublicKeyInfoOwned) -> Option<AlgorithmId> {
    if spki.algorithm.oid == RSA_ENCRYPTION {
        let key = RsaPublicKey::from_der(spki.subject_public_key.as_bytes()?).ok()?;
        return match key.modulus.as_bytes().len() {
            128 => Some(AlgorithmId::Rsa1024),
            256 => Some(AlgorithmId::Rsa2048),
            384 => Some(AlgorithmId::Rsa3072),
            512 => Some(AlgorithmId::Rsa4096),
            _ => None,
        };
    }
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return None;
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()?
        .decode_as::<ObjectIdentifier>()
        .ok()?;
    match curve {
        SECP_256_R_1 => Some(AlgorithmId::EccP256),
        SECP_384_R_1 => Some(AlgorithmId::EccP384),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::BitString;

    fn alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    fn rsa_spki(modulus_len: usize) -> SubjectPublicKeyInfoOwned {
        let mut modulus = vec![0xc5; modulus_len];
        modulus[modulus_len - 1] = 0x01;
        let key = RsaPublicKey {
            modulus: UintRef::new(&modulus).unwrap(),
            public_exponent: UintRef::new(&[0x01, 0x00, 0x01]).unwrap(),
        }
        .to_der()
        .unwrap();
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: RSA_ENCRYPTION,
                parameters: Some(Any::null()),
            },
            subject_public_key: BitString::from_bytes(&key).unwrap(),
        }
    }

    fn ec_spki(curve: ObjectIdentifier, point_len: usize) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(&curve).unwrap()),
            },
            subject_public_key: BitString::from_bytes(&vec![0x04; point_len]).unwrap(),
        }
    }

    #[test]
    fn key_algorithm_follows_the_modulus_and_the_curve() {
        assert_eq!(key_algorithm(&rsa_spki(256)), Some(AlgorithmId::Rsa2048));
        assert_eq!(key_algorithm(&rsa_spki(384)), Some(AlgorithmId::Rsa3072));
        assert_eq!(key_algorithm(&rsa_spki(512)), Some(AlgorithmId::Rsa4096));
        assert_eq!(key_algorithm(&rsa_spki(200)), None);
        assert_eq!(
            key_algorithm(&ec_spki(SECP_256_R_1, 65)),
            Some(AlgorithmId::EccP256)
        );
        assert_eq!(
            key_algorithm(&ec_spki(SECP_384_R_1, 97)),
            Some(AlgorithmId::EccP384)
        );
        // P-521, which the card does not hold.
        let p521 = ObjectIdentifier::new_unwrap("1.3.132.0.35");
        assert_eq!(key_algorithm(&ec_spki(p521, 133)), None);
    }

    #[test]
    fn emsa_pkcs1_v1_5_matches_rfc_8017() {
        let digest = [0x5a; 32];
        let em = emsa_pkcs1_v1_5(ID_SHA_256, &digest, 256).unwrap();
        // The DigestInfo prefix for SHA-256 given in RFC 8017, section 9.2, note 1.
        let prefix = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        let t_len = prefix.len() + digest.len();
        assert_eq!(em.len(), 256);
        assert_eq!(&em[..2], &[0x00, 0x01]);
        assert!(em[2..256 - t_len - 1].iter().all(|b| *b == 0xff));
        assert_eq!(em[256 - t_len - 1], 0x00);
        assert_eq!(&em[256 - t_len..256 - digest.len()], &prefix);
        assert_eq!(&em[256 - digest.len()..], &digest);
        // Too short a modulus for eight octets of padding.
        assert!(emsa_pkcs1_v1_5(ID_SHA_512, &[0; 64], 64 + 19 + 10).is_none());
    }

    #[test]
    fn signature_input_pairs_the_algorithm_with_the_key() {
        let sha256 = [0x11; 32];
        let sha384 = [0x22; 48];
        // RSA: the encoding, for a PKCS #1 v1.5 algorithm and a digest of its hash's length.
        let em = signature_input(
            AlgorithmId::Rsa2048,
            &alg(SHA_256_WITH_RSA_ENCRYPTION),
            &sha256,
        )
        .unwrap();
        assert_eq!(em.len(), 256);
        assert!(signature_input(
            AlgorithmId::Rsa2048,
            &alg(SHA_384_WITH_RSA_ENCRYPTION),
            &sha256
        )
        .is_none());
        assert!(signature_input(AlgorithmId::Rsa2048, &alg(ECDSA_WITH_SHA_256), &sha256).is_none());
        // EC: the digest, cut to the order's length when it is longer.
        assert_eq!(
            signature_input(AlgorithmId::EccP256, &alg(ECDSA_WITH_SHA_256), &sha256).unwrap(),
            sha256
        );
        assert_eq!(
            signature_input(AlgorithmId::EccP256, &alg(ECDSA_WITH_SHA_384), &sha384).unwrap(),
            sha384[..32]
        );
        assert_eq!(
            signature_input(AlgorithmId::EccP384, &alg(ECDSA_WITH_SHA_256), &sha256).unwrap(),
            sha256
        );
        assert!(signature_input(
            AlgorithmId::EccP256,
            &alg(SHA_256_WITH_RSA_ENCRYPTION),
            &sha256
        )
        .is_none());
    }
}
