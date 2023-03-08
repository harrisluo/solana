use {
    crate::medium::{RemoteKeypairMedium, RemoteKeypairMediumError},
    openpgp_card::{
        algorithm::{Algo, Curve, EccAttrs},
        card_do::{ApplicationIdentifier, Fingerprint, KeyGenerationTime, KeyStatus, UIF},
        crypto_data::{EccType, PublicKeyMaterial, Hash},
        KeyType,
        OpenPgp,
        SmartcardError,
        OpenPgpTransaction
    },
    openpgp_card_pcsc::PcscBackend,
    pinentry::PassphraseInput,
    secrecy::ExposeSecret,
    sha1::Sha1,
    solana_sdk::{
        pubkey::Pubkey,
        signature::{Signature, Signer, SignerError},
    },
    std::{
        cell::RefCell,
        error,
    },
    thiserror::Error,
    uriparse::{URIReference, URIReferenceError},
};

/// Locator for smart cards supporting OpenPGP connected to the local machine.
/// 
/// Field `aid` contains a data struct with fields for application ID, version,
/// manufacturer ID (of the smart card), and serial number. An instance of
/// `ApplicationIdentifier` is logically equivalent to an AID string as
/// specified in the OpenPGP specification v3.4 (section 4.2.1), used to
/// uniquely identify an instance of an OpenPGP application on a unique smart
/// card.
/// 
/// A null `aid` indicates the default locator which chooses the first smart
/// card supporting OpenPGP that it finds connected to the machine.
#[derive(Debug, PartialEq, Eq)]
pub struct Locator {
    pub aid: Option<ApplicationIdentifier>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LocatorError {
    #[error("failed to parse OpenPGP AID: {0}")]
    IdentifierParseError(String),
    #[error(transparent)]
    UriReferenceError(#[from] URIReferenceError),
    #[error("mismatched scheme")]
    MismatchedScheme,
}

impl TryFrom<&URIReference<'_>> for Locator {
    type Error = LocatorError;

    /// Extract a locator from a URI.
    /// 
    /// "pgpcard://" => Default locator.
    /// 
    /// "pgpcard://D2760001240103040006123456780000" => Locator pointing to a
    /// OpenPGP instance identifiable by AID D2760001240103040006123456780000.
    /// As per the OpenPGP specification:
    ///   * AID must be a 16-byte hexadecimal string (32 digits).
    ///   * D276000124 => AID preamble, fixed across all AIDs
    ///   * 01         => application ID, fixed to 01 == OpenPGP
    ///   * 0304       => OpenPGP version, 3.4 in this case
    ///   * 0006       => unique manufacturer ID, Yubico in this case
    ///   * 12345678   => smart card serial number
    ///   * 0000       => reserved for future use
    /// 
    /// No other URI formats are valid.
    fn try_from(uri: &URIReference<'_>) -> Result<Self, Self::Error> {
        let scheme = uri.scheme().map(|s| s.as_str().to_ascii_lowercase());
        let ident = uri.host().map(|h| h.to_string());
        
        match (scheme, ident) {
            (Some(scheme), Some(ident)) if scheme == "pgpcard" => {
                if ident.is_empty() {
                    return Ok(Self { aid: None });
                }
                if ident.len() % 2 != 0 {
                    return Err(LocatorError::IdentifierParseError("OpenPGP AID must have even length".to_string()));
                }
                let mut ident_bytes = Vec::<u8>::new();
                for i in (0..ident.len()).step_by(2) {
                    ident_bytes.push(u8::from_str_radix(&ident[i..i + 2], 16).map_err(
                        |_| LocatorError::IdentifierParseError("non-hex character found in identifier".to_string())
                    )?);
                }
                Ok(Self {
                    aid: Some(ident_bytes.as_slice().try_into().map_err(
                        |_| LocatorError::IdentifierParseError("invalid identifier format".to_string())
                    )?),
                })
            },
            (Some(scheme), None) if scheme == "pgpcard" => Ok(Self { aid: None }),
            _ => Err(LocatorError::MismatchedScheme),
        }
    }
}

/// An ongoing connection to the OpenPGP application on a smart card.
/// 
/// Field `pgp: OpenPgp` is a long-lived card access object. When OpenpgpCard
/// is initialized via TryFrom<&Locator>, this object contains a `PcscBackend`
/// connector object that communicates with the card using PC/SC.
/// 
/// Actual operations on the card are done through short-lived 
/// OpenPgpTransaction objects that are instantiated from `OpenPgp` on an ad
/// hoc basis. There should only exist one active OpenPgpTransaction at a time.
/// 
/// Field `pin_verified` indicates whether a successful PIN verification has
/// already happened in the past (specifically for PW1 used to authorize
/// signing). This allows redundant PIN verification to be skipped for cards
/// that require only a single successful PIN entry per session.
pub struct OpenpgpCard {
    pgp: RefCell<OpenPgp>,
    pin_verified: RefCell<bool>,
}

impl TryFrom<&Locator> for OpenpgpCard {
    type Error = openpgp_card::Error;

    fn try_from(locator: &Locator) -> Result<Self, Self::Error> {
        let pcsc_identifier = locator.aid.as_ref().map(|x| x.ident());
        let backend = match pcsc_identifier {
            Some(ident) => PcscBackend::open_by_ident(&ident, None)?,
            None => {
                let mut cards = PcscBackend::cards(None)?;
                if cards.is_empty() {
                    return Err(openpgp_card::Error::Smartcard(SmartcardError::NoReaderFoundError))
                } else {
                    cards.remove(0)
                }
            }
        };

        // Start up the long-lived OpenPgp backend connection object which will
        // be persisted as a field in the `OpenpgpCard` struct.
        let pgp = OpenPgp::new::<PcscBackend>(backend.into());

        Ok(Self {
            pgp: RefCell::new(pgp),
            pin_verified: RefCell::new(false),
        })
    }
}

impl Signer for OpenpgpCard {
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        let mut pgp_mut = self.pgp.borrow_mut();
        let opt = &mut pgp_mut.transaction().map_err(
            |e| SignerError::Connection(format!("could not start transaction with card: {}", e))
        )?;

        // Verify smart card's PGP signing key is an ed25519 key using EdDSA
        // and extract the pubkey as bytes.
        let pk_material = opt.public_key(openpgp_card::KeyType::Signing).map_err(
            |e| SignerError::Connection(format!("could not find signing keypair on card: {}", e))
        )?;
        let pubkey = get_pubkey_from_pk_material(pk_material).map_err(
            |e| SignerError::Connection(format!("public key on card is invalid: {}", e))
        )?;
        Ok(pubkey)
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // Verify that card has valid signing key
        self.try_pubkey()?;

        let mut pgp_mut = self.pgp.borrow_mut();
        let opt = &mut pgp_mut.transaction().map_err(
            |e| SignerError::Connection(format!("could not start transaction with card: {}", e))
        )?;
        let card_info: OpenpgpCardInfo = opt.try_into().map_err(
            |e| SignerError::Connection(format!("could not get card info: {}", e))
        )?;

        // Prompt user for PIN verification if and only if
        //   * Card indicates PIN is only valid for one PSO:CDS command at a time, or
        //   * PIN has not yet been entered for the first time.
        if card_info.pin_cds_valid_once || !*self.pin_verified.borrow() {
            let mut pin = get_pin_from_user_as_bytes(&card_info, false, true).map_err(
                |e| SignerError::Custom(e.to_string())
            )?;
            while opt.verify_pw1_sign(pin.as_bytes()).is_err() {
                pin = get_pin_from_user_as_bytes(&card_info, false, false).map_err(
                    |e| SignerError::Custom(e.to_string())
                )?;
            }
            *self.pin_verified.borrow_mut() = true;
        }

        // Await user touch confirmation if and only if
        //   * Card supports touch confirmation, and
        //   * Touch policy set anything other than "off".
        if let Some(signing_uif) = card_info.signing_uif {
            if signing_uif.touch_policy().touch_required() {
                println!("Awaiting touch confirmation...");
            }
        }

        // Delegate message signing to card
        let hash = Hash::EdDSA(message);
        let sig = opt.signature_for_hash(hash).map_err(
            |e| SignerError::Protocol(format!("card failed to sign message: {}", e))
        )?;

        Ok(Signature::new(&sig[..]))
    }

    fn is_interactive(&self) -> bool {
        true
    }
}

impl RemoteKeypairMedium for OpenpgpCard {
    fn has_existing_keypair(&self) -> Result<bool, RemoteKeypairMediumError> {
        let mut pgp_mut = self.pgp.borrow_mut();
        let opt = &mut pgp_mut.transaction()?;
        let ard = opt.application_related_data()?;
        if let Some(key_info) = ard.key_information()? {
            // Signing keypair exists on card if and only if signing key status
            // is anything other than NotPresent.
            Ok(key_info.sig_status() != KeyStatus::NotPresent)
        } else {
            Err(RemoteKeypairMediumError::Custom("could not get signing key status".to_string()))
        }
    }

    fn generate_keypair(&self) -> Result<Pubkey, RemoteKeypairMediumError> {
        let mut pgp_mut = self.pgp.borrow_mut();
        let opt = &mut pgp_mut.transaction()?;
        let card_info: OpenpgpCardInfo = opt.try_into()?;

        // Prompt user for admin PIN verification
        let mut pin = get_pin_from_user_as_bytes(&card_info, true, true).map_err(
            |e| RemoteKeypairMediumError::Custom(e.to_string())
        )?;
        while opt.verify_pw3(pin.as_bytes()).is_err() {
            pin = get_pin_from_user_as_bytes(&card_info, true, false).map_err(
                |e| RemoteKeypairMediumError::Custom(e.to_string())
            )?;
        }

        // Call keygen primitive on card
        let (pk_material, _) = opt.generate_key(
            get_pgp_key_fingerprint,
            KeyType::Signing,
            Some(&Algo::Ecc(EccAttrs::new(
                EccType::EdDSA,
                Curve::Ed25519,
                None,
            ))),
        )?;
        Ok(get_pubkey_from_pk_material(pk_material)?)
    }
}

/// Data struct for convenience.
#[derive(Debug)]
struct OpenpgpCardInfo {
    aid: ApplicationIdentifier,
    cardholder_name: String,
    signing_uif: Option<UIF>,
    pin_cds_valid_once: bool,
}

impl TryFrom<&mut OpenPgpTransaction<'_>> for OpenpgpCardInfo {
    type Error = openpgp_card::Error;

    fn try_from(opt: &mut OpenPgpTransaction) -> Result<Self, Self::Error> {
        let ard = opt.application_related_data()?;
        Ok(OpenpgpCardInfo {
            aid: ard.application_id()?,
            cardholder_name: String::from_utf8_lossy(
                opt.cardholder_related_data()?.name().get_or_insert(b"null")
            ).to_string(),
            signing_uif: ard.uif_pso_cds()?,
            pin_cds_valid_once: ard.pw_status_bytes()?.pw1_cds_valid_once(),
        })
    }
}

fn get_pubkey_from_pk_material(pk_material: PublicKeyMaterial) -> Result<Pubkey, openpgp_card::Error> {
    let pk_bytes: [u8; 32] = match pk_material {
        PublicKeyMaterial::E(pk) => match pk.algo() {
            Algo::Ecc(ecc_attrs) => {
                if ecc_attrs.ecc_type() != EccType::EdDSA || ecc_attrs.curve() != Curve::Ed25519 {
                    return Err(openpgp_card::Error::UnsupportedAlgo(
                        format!("expected Ed25519 key, got {:?}", ecc_attrs.curve())
                    ));
                }
                pk.data().try_into().map_err(
                    |e| openpgp_card::Error::ParseError(format!("key on card is malformed: {}", e))
                )?
            },
            _ => return Err(openpgp_card::Error::UnsupportedAlgo("expected ECC key, got RSA".to_string())),
        }
        _ => return Err(openpgp_card::Error::UnsupportedAlgo("expected ECC key, got RSA".to_string())),
    };
    Ok(Pubkey::from(pk_bytes))
}

fn get_pin_from_user_as_bytes(
    card_info: &OpenpgpCardInfo,
    admin: bool,
    first_attempt: bool,
) -> Result<String, Box<dyn error::Error>> {
    let description = format!(
        "\
            Please unlock the card%0A\
            %0A\
            Manufacturer: {}%0A\
            Serial: {:X}%0A\
            Cardholder: {}\
            {}\
        ",
        card_info.aid.manufacturer_name(),
        card_info.aid.serial(),
        card_info.cardholder_name,
        if first_attempt { "" } else { "%0A%0A##### INVALID PIN #####" },
    );
    let pin = if let Some(mut input) = PassphraseInput::with_default_binary() {
        input.with_description(description.as_str()).with_prompt(
            if admin { "Admin PIN" } else { "PIN" }
        ).interact().map_err(|e| e.to_string())?
    } else {
        return Err("pinentry binary not found, please install".into());
    };
    Ok(pin.expose_secret().to_owned())
}

/// Derive a PGP fingerprint to associate with the generated PGP key, using the
/// algorithm specified in [RFC 4880 Section 12.2][rfc4880]. The implementation
/// below is specific to ed25519 signing keys.
/// 
/// [rfc4880]: https://www.rfc-editor.org/rfc/rfc4880#section-12.2
fn get_pgp_key_fingerprint(
    pkm: &PublicKeyMaterial,
    kgt: KeyGenerationTime,
    _key_type: KeyType,
) -> Result<Fingerprint, openpgp_card::Error> {
    let mut hasher = Sha1::new();
    hasher.update(&[0x99u8]);     // indicator byte (1 B)
    hasher.update(&[0u8, 51u8]);  // length of data to follow, always 51 bytes for ed25519 keys (2 B)
    hasher.update(&[4u8]);        // OpenPGP message version (1 B)
    hasher.update(&kgt.get().to_be_bytes());  // key creation time (4 B)
    hasher.update(&[              // ECC algorithm info, hardcoded for ed25519 (14 B)
        0x16, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01,
        0xda, 0x47, 0x0f, 0x01, 0x01, 0x07, 0x40,
    ]);
    match pkm {
        PublicKeyMaterial::E(eccpub) => {
            hasher.update(eccpub.data());  // ed25519 public key (32 B)
        },
        _ => return Err(openpgp_card::Error::UnsupportedAlgo("expected ECC key, got RSA".to_string())),
    };
    Ok(Fingerprint::from(hasher.digest().bytes()))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        openpgp_card::crypto_data::{EccPub, RSAPub},
    };

    #[test]
    fn test_parse_locator() {
        // no identifier in URI => default locator
        let uri = URIReference::try_from("pgpcard://").unwrap();
        assert_eq!(
            Locator::try_from(&uri),
            Ok(Locator { aid: None }),
        );

        // valid identifier in URI
        let uri = URIReference::try_from("pgpcard://D2760001240103040006123456780000").unwrap();
        let expected_ident_bytes: [u8; 16] = [
            0xD2, 0x76, 0x00, 0x01, 0x24,   // preamble
            0x01,                           // application id (OpenPGP)
            0x03, 0x04,                     // version
            0x00, 0x06,                     // manufacturer id
            0x12, 0x34, 0x56, 0x78,         // serial number
            0x00, 0x00                      // reserved
        ];
        assert_eq!(
            Locator::try_from(&uri),
            Ok(Locator { aid: Some(ApplicationIdentifier::try_from(&expected_ident_bytes[..]).unwrap()) }),
        );

        // non-hex character in identifier
        let uri = URIReference::try_from("pgpcard://G2760001240103040006123456780000").unwrap();
        assert_eq!(
            Locator::try_from(&uri),
            Err(LocatorError::IdentifierParseError("non-hex character found in identifier".to_string())),
        );

        // invalid identifier length
        let uri = URIReference::try_from("pgpcard://D27600012401030400061234567800").unwrap();
        assert_eq!(
            Locator::try_from(&uri),
            Err(LocatorError::IdentifierParseError("invalid identifier format".to_string())),
        );
    }

    #[test]
    fn test_get_pubkey_from_pk_material() {
        // Test valid ed25519 pubkey
        let pk_bytes: [u8; 32] = [
            0x5B, 0x92, 0xEF, 0x74, 0xA4, 0xF7, 0x9D, 0xAB,
            0xF6, 0x8C, 0x15, 0x94, 0x3F, 0x9A, 0x01, 0x81,
            0xF9, 0x39, 0xD0, 0xF3, 0xA0, 0x1E, 0x4F, 0x88,
            0x0E, 0xEC, 0x7B, 0x51, 0x93, 0xC2, 0x24, 0x69,
        ];
        let pk_material = PublicKeyMaterial::E(EccPub::new(
            pk_bytes.to_vec(),
            Algo::Ecc(EccAttrs::new(EccType::EdDSA, Curve::Ed25519, None)),
        ));
        assert_eq!(
            get_pubkey_from_pk_material(pk_material).unwrap(),
            Pubkey::from(pk_bytes),
        );

        // Test malformed ed25519 pubkey
        let pk_material = PublicKeyMaterial::E(EccPub::new(
            vec![
                0x5B, 0x92, 0xEF, 0x74, 0xA4, 0xF7, 0x9D, 0xAB,
                0xF6, 0x8C, 0x15, 0x94, 0x3F, 0x9A, 0x01, 0x81,
                0xF9, 0x39, 0xD0, 0xF3, 0xA0, 0x1E, 0x4F, 0x88,
                0x0E, 0xEC, 0x7B, 0x51, 0x93, 0xC2, 0x24, 0x69, 0x00,
            ],
            Algo::Ecc(EccAttrs::new(EccType::EdDSA, Curve::Ed25519, None)),
        ));
        assert!(matches!(
            get_pubkey_from_pk_material(pk_material),
            Err(openpgp_card::Error::ParseError(_)),
        ));

        // Test unsupported algorithms
        let pk_material = PublicKeyMaterial::E(EccPub::new(
            pk_bytes.to_vec(),
            Algo::Ecc(EccAttrs::new(EccType::EdDSA, Curve::Ed448, None)),
        ));
        assert!(matches!(
            get_pubkey_from_pk_material(pk_material),
            Err(openpgp_card::Error::UnsupportedAlgo(_)),
        ));
        let pk_material = PublicKeyMaterial::R(RSAPub::new(
            vec![0u8; 0], vec![0u8; 0]
        ));
        assert!(matches!(
            get_pubkey_from_pk_material(pk_material),
            Err(openpgp_card::Error::UnsupportedAlgo(_)),
        ));
    }

    #[test]
    fn test_get_fingerprint() {
        let pkm = PublicKeyMaterial::E(EccPub::new(
            vec![
                0x5B, 0x92, 0xEF, 0x74, 0xA4, 0xF7, 0x9D, 0xAB,
                0xF6, 0x8C, 0x15, 0x94, 0x3F, 0x9A, 0x01, 0x81,
                0xF9, 0x39, 0xD0, 0xF3, 0xA0, 0x1E, 0x4F, 0x88,
                0x0E, 0xEC, 0x7B, 0x51, 0x93, 0xC2, 0x24, 0x69,
            ],
            Algo::Ecc(EccAttrs::new(
                EccType::EdDSA,
                Curve::Ed25519,
                None,
            ))
        ));
        let kgt: KeyGenerationTime = 1677533611.into();
        let key_type = KeyType::Signing;
        let fingerprint = get_pgp_key_fingerprint(&pkm, kgt, key_type).unwrap();
        assert_eq!(
            fingerprint.as_bytes(),
            [
                0xf2, 0xcf, 0x3e, 0x18, 0x39, 0xe3, 0x60, 0xbf, 0x51, 0x8b,
                0x65, 0xba, 0x78, 0x05, 0x20, 0xe8, 0x80, 0xa9, 0x6c, 0xd3,
            ],
        );
    }
}
