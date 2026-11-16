//! CMS through the keys on an attached YubiKey, crossed with certval-cms's RustCrypto software.
//!
//! Each key on the card with a certificate is used for what its slot is for. The Digital Signature
//! key signs a SignedData, found by signer identifier through `YubiKeyIdentities`, which software
//! verifies. The Key Management key and the retired key management keys decrypt an EnvelopedData
//! software encrypts to their certificates, the credential found by recipient identifier the same
//! way: key transport for an RSA key, key agreement for an EC key. The PIV Authentication and
//! Card Authentication keys must be found by neither lookup.
//!
//! Every certificate is validated as well: certval builds a path from it to a trust anchor in a
//! store from certval-stores, `CERTVAL_YUBIKEY_STORE` or by default the Purebred development store,
//! with revocation checking off, before the card signs with or decrypts for its key.
//!
//! The card is not reached unless `CERTVAL_YUBIKEY_PIN` names its PIN; without it the test says
//! so and passes. `CERTVAL_YUBIKEY_SERIAL` chooses a card when more than one is attached. Nothing
//! is written to the card: the keys and certificates already on it are what is tested, so it
//! needs at least one key with a certificate.
//!
//! ```sh
//! CERTVAL_YUBIKEY_PIN=123456 cargo test --test cms -- --nocapture
//! ```

use std::sync::Arc;

use certval::{CertificationPathSettings, PkiEnvironment};
use certval_cms::{
    recipient_identifier, rsa_pss, signer_identifier, CmsEnvironment, ContentEncryptionAlgorithm,
    DigestAlgorithm, EnvelopedDataBuilder, KeyAgreeRecipient, KeyAgreementAlgorithm,
    KeyTransRecipient, KeyTransportAlgorithm, KeyWrapAlgorithm, RecipientCredentialSource,
    SignedDataBuilder, Signer, SignerPolicy, SigningCredentialLookup, SigningCredentialSource,
    Vetting,
};
use certval_stores_core::prepare_certval_environment;
use certval_yubikey::{YubiKeyCard, YubiKeyIdentities};
use cms::content_info::ContentInfo;
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION};
use getrandom::SysRng;
use rand_core::UnwrapErr;
use x509_cert::Certificate;
use yubikey::piv::SlotId;

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] = b"certval-yubikey, longer than one AES block so that padding is exercised";

const DIGESTS: [DigestAlgorithm; 3] = [
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
];

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

/// certval's software, with the trust anchors and CA certificates of the store `store`.
fn pki_environment(store: &str) -> Arc<PkiEnvironment> {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    prepare_certval_environment(&[certval_stores_pbdev::provider()], &mut pe, store)
        .unwrap_or_else(|e| panic!("the store {store} loads: {e:?}"));
    Arc::new(pe)
}

/// The defaults, with revocation checking off: the development PKI publishes no CRLs.
fn settings() -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::default();
    cps.set_check_revocation_status(false);
    cps
}

/// RustCrypto for everything, over `pe`, with the card's keys as recipient and signing credentials
/// when `identities` is given.
fn environment(pe: &Arc<PkiEnvironment>, identities: Option<&YubiKeyIdentities>) -> CmsEnvironment {
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env.set_pki_environment(pe.clone());
    if let Some(identities) = identities {
        env.add_recipient_credential_source(identities.clone());
        env.add_signing_credential_source(identities.clone());
    }
    env
}

/// Neither lookup finds `cert`'s key, as for an authentication key.
fn is_not_offered(
    env: &CmsEnvironment,
    identities: &YubiKeyIdentities,
    cert: &Certificate,
    name: &str,
) {
    let sid = signer_identifier(cert).unwrap();
    let signing = identities
        .find_signing_credentials(env, SigningCredentialLookup::Identifier(&sid))
        .unwrap();
    assert!(signing.is_empty(), "{name}: offered for signing");
    let rid = recipient_identifier(cert).unwrap();
    let recipient = identities.find_recipient_credential(env, &rid).unwrap();
    assert!(recipient.is_none(), "{name}: offered for decryption");
    println!("{name}: an authentication key, offered for neither signing nor decryption");
}

/// The card signs with `cert`'s key, found by signer identifier, and software verifies, validating
/// the signer's certificate.
fn signs(
    card: &CmsEnvironment,
    software: &CmsEnvironment,
    cps: &CertificationPathSettings,
    cert: &Certificate,
    name: &str,
) {
    let rsa = cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid
        == RSA_ENCRYPTION;
    for digest in DIGESTS {
        let sid = signer_identifier(cert).unwrap();
        let ci = SignedDataBuilder::new(MESSAGE)
            .add_signer(Signer::by_identifier(sid).digest(digest))
            .build(card)
            .unwrap_or_else(|e| panic!("{name} {digest:?}: signing: {e}"))
            .content_info;
        let verified = software
            .verify_signed_data(&ci, None, Some(cps), SignerPolicy::All)
            .unwrap_or_else(|e| panic!("{name} {digest:?}: verifying: {e}"));
        assert_eq!(verified.content, MESSAGE, "{name} {digest:?}");
        assert!(
            matches!(verified.signers[0].vetting, Vetting::Validated(_)),
            "{name} {digest:?}: the signer's certificate was not validated"
        );
        println!("{name}: signed with {digest:?}, verified by software, certificate validated");

        // RSASSA-PSS is declined, and with no other credential for the key, signing fails.
        if rsa {
            let sid = signer_identifier(cert).unwrap();
            let pss = SignedDataBuilder::new(MESSAGE)
                .add_signer(
                    Signer::by_identifier(sid)
                        .digest(digest)
                        .signature_algorithm(rsa_pss(digest).unwrap()),
                )
                .build(card);
            assert!(pss.is_err(), "{name} {digest:?}: PSS was not declined");
        }
    }
}

fn envelop(
    env: &CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    recipient: impl certval_cms::RecipientInfoBuilder<Rng = Rng>,
) -> ContentInfo {
    EnvelopedDataBuilder::new(MESSAGE, alg)
        .unwrap()
        .add_recipient(recipient)
        .build_content_info(env, &mut rng())
        .unwrap_or_else(|e| panic!("building: {e}"))
}

fn assert_card_decrypts(card: &CmsEnvironment, ci: &ContentInfo, name: &str) {
    let decrypted = card
        .decrypt_enveloped_data(ci, None)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(decrypted.content.as_slice(), MESSAGE, "{name}");
    println!("{name}: certificate validated, encrypted by software, decrypted by the card");
}

/// Software validates `cert` and encrypts to it by key transport, and the card decrypts.
fn decrypts_key_transport(
    card: &CmsEnvironment,
    software: &CmsEnvironment,
    cps: &CertificationPathSettings,
    cert: &Certificate,
    name: &str,
) {
    for content in [
        ContentEncryptionAlgorithm::Aes128Cbc,
        ContentEncryptionAlgorithm::Aes256Cbc,
    ] {
        let r = KeyTransRecipient::from_certificate(
            software,
            cert,
            Some(cps),
            KeyTransportAlgorithm::RsaPkcs1v15,
        )
        .unwrap_or_else(|e| panic!("{name}: the recipient's certificate: {e}"));
        let ci = envelop(software, content, r);
        assert_card_decrypts(card, &ci, &format!("{name} PKCS #1 v1.5 {content:?}"));
    }
}

/// Software validates `cert` and encrypts to it by key agreement, and the card decrypts.
fn decrypts_key_agreement(
    card: &CmsEnvironment,
    software: &CmsEnvironment,
    cps: &CertificationPathSettings,
    cert: &Certificate,
    name: &str,
) {
    for (alg, wrap) in [
        (KeyAgreementAlgorithm::EcdhSha256, KeyWrapAlgorithm::Aes128),
        (KeyAgreementAlgorithm::EcdhSha384, KeyWrapAlgorithm::Aes256),
        (KeyAgreementAlgorithm::EcdhSha512, KeyWrapAlgorithm::Aes256),
    ] {
        for ukm in [None, Some(b"user keying material".to_vec())] {
            let case = format!("{name} {alg:?} {wrap:?} ukm={}", ukm.is_some());
            let r = KeyAgreeRecipient::from_certificate(software, cert, Some(cps), alg, wrap, ukm)
                .unwrap_or_else(|e| panic!("{case}: the recipient's certificate: {e}"));
            let ci = envelop(software, ContentEncryptionAlgorithm::Aes256Cbc, r);
            assert_card_decrypts(card, &ci, &case);
        }
    }
}

#[test]
fn signs_and_decrypts_with_the_keys_on_the_card() {
    let Ok(pin) = std::env::var("CERTVAL_YUBIKEY_PIN") else {
        println!("skipped, CERTVAL_YUBIKEY_PIN is not set");
        return;
    };
    let serial = std::env::var("CERTVAL_YUBIKEY_SERIAL")
        .ok()
        .map(|s| s.parse().expect("CERTVAL_YUBIKEY_SERIAL is a number"));
    let card = Arc::new(YubiKeyCard::open(serial, pin.as_bytes()).expect("the YubiKey opens"));
    let certificates: Vec<_> = card
        .certificates()
        .map(|(slot, cert)| (slot, cert.clone()))
        .collect();
    assert!(
        !certificates.is_empty(),
        "the YubiKey holds no key with a certificate this crate uses"
    );

    let store = std::env::var("CERTVAL_YUBIKEY_STORE")
        .unwrap_or_else(|_| certval_stores_pbdev::PUREBRED_DEV.to_string());
    let pe = pki_environment(&store);
    let cps = settings();
    let identities = YubiKeyIdentities::new(card);
    let card_env = environment(&pe, Some(&identities));
    let software = environment(&pe, None);
    let mut performed = 0;
    for (slot, cert) in &certificates {
        let name = format!("{slot:?} ({})", cert.tbs_certificate().subject());
        let key = cert
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid;
        match slot {
            SlotId::Signature => {
                signs(&card_env, &software, &cps, cert, &name);
                performed += 1;
            }
            SlotId::KeyManagement | SlotId::Retired(_) => {
                if key == RSA_ENCRYPTION {
                    decrypts_key_transport(&card_env, &software, &cps, cert, &name);
                } else if key == ID_EC_PUBLIC_KEY {
                    decrypts_key_agreement(&card_env, &software, &cps, cert, &name);
                }
                performed += 1;
            }
            _ => is_not_offered(&card_env, &identities, cert, &name),
        }
    }
    assert!(
        performed > 0,
        "no key on the YubiKey is in the Digital Signature, Key Management or a retired slot"
    );
}
