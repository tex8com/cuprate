use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use voprf::{
    BlindedElement, EvaluationElement, Group, Proof, Ristretto255, VoprfClient, VoprfServer,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::name::{AddressKind, Network, PublicAddress};

const PHONE_INPUT_DOMAIN: &[u8] = b"TEX8/MFW/phone-input/v1";
const PHONE_TOKEN_DOMAIN: &[u8] = b"TEX8/MFW/phone-token/2of2/v1";
const PAIR_ID_DOMAIN: &[u8] = b"TEX8/MFW/phone-pair/v1";
const KEY_ID_DOMAIN: &[u8] = b"TEX8/MFW/hpke-key-id/v1";
const AUTH_DOMAIN: &[u8] = b"TEX8/MFW/phone-participant-authorization/v1";
const PERMIT_REFRESH_DOMAIN: &[u8] = b"TEX8/MFW/phone-permit-refresh/v1";
const PARTICIPANT_REVOCATION_DOMAIN: &[u8] = b"TEX8/MFW/phone-participant-revocation/v1";
const ENVELOPE_SIGNATURE_DOMAIN: &[u8] = b"TEX8/MFW/contact-envelope/v1";
const ASK_ENVELOPE_SIGNATURE_DOMAIN: &[u8] = b"TEX8/MFW/ask-envelope/v1";
const ASK_MESSAGE_ID_DOMAIN: &[u8] = b"TEX8/MFW/ask-message-id/v1";
const ASK_MAILBOX_POLL_DOMAIN: &[u8] = b"TEX8/MFW/ask-mailbox-poll/v1";
const CONTACT_REVOCATION_DOMAIN: &[u8] = b"TEX8/MFW/contact-revocation/v1";
const SNAPSHOT_SIGNATURE_DOMAIN: &[u8] = b"TEX8/MFW/directory-snapshot/v1";
const HPKE_INFO: &[u8] = b"TEX8 MFW private contact card v1";
const ASK_HPKE_INFO: &[u8] = b"TEX8 MFW private contact ask v1";

const CARD_MAGIC: &[u8; 8] = b"MFWCARD1";
const ASK_REQUEST_MAGIC: &[u8; 8] = b"MFWASKR1";
const ASK_RESPONSE_MAGIC: &[u8; 8] = b"MFWASKP1";
const ASK_ENVELOPE_MAGIC: &[u8; 8] = b"MFWASKE1";
const ASK_MAILBOX_POLL_MAGIC: &[u8; 8] = b"MFWPOL01";
const AUTH_MAGIC: &[u8; 8] = b"MFWAUTH1";
const PERMIT_REFRESH_MAGIC: &[u8; 8] = b"MFWPERM1";
const PARTICIPANT_REVOCATION_MAGIC: &[u8; 8] = b"MFWPRV01";
const ENVELOPE_MAGIC: &[u8; 8] = b"MFWENV01";
const CONTACT_REVOCATION_MAGIC: &[u8; 8] = b"MFWCRV01";
const SNAPSHOT_MAGIC: &[u8; 8] = b"MFWSNAP1";
const VERSION: u8 = 1;

pub const CONTACT_CARD_BYTES: usize = 256;
pub const CONTACT_CIPHERTEXT_BYTES: usize = CONTACT_CARD_BYTES + 16;
pub const ASK_MESSAGE_BYTES: usize = 256;
pub const ASK_CIPHERTEXT_BYTES: usize = ASK_MESSAGE_BYTES + 16;
pub const ASK_ENVELOPE_BYTES: usize = 592;
pub const ASK_MAILBOX_POLL_BYTES: usize = 170;
pub const PARTICIPANT_RECORD_BYTES: usize = 201;
pub const PERMIT_REFRESH_REQUEST_BYTES: usize = 153;
pub const PARTICIPANT_REVOCATION_BYTES: usize = 169;
pub const CONTACT_ENVELOPE_BYTES: usize = 537;
pub const CONTACT_REVOCATION_BYTES: usize = 193;
pub const MAX_CONTACT_CARD_LIFETIME_SECONDS: u64 = 31 * 24 * 60 * 60;
pub const MAX_ASK_MESSAGE_LIFETIME_SECONDS: u64 = 15 * 60;
pub const MAX_ASK_MAILBOX_POLL_LIFETIME_SECONDS: u64 = 5 * 60;
pub const MAX_PARTICIPANT_LIFETIME_SECONDS: u64 = 31 * 24 * 60 * 60;
pub const MAX_PERMIT_REFRESH_LIFETIME_SECONDS: u64 = 5 * 60;
pub const MAX_NUMBER_REASSIGNMENT_COOLDOWN_SECONDS: u64 = 31 * 24 * 60 * 60;
pub const MAX_SNAPSHOT_LIFETIME_SECONDS: u64 = 48 * 60 * 60;
pub const MAX_SNAPSHOT_PARTICIPANTS: usize = 250_000;
pub const MAX_SNAPSHOT_ENTRIES: usize = 500_000;
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
pub const VOPRF_CLIENT_STATE_BYTES: usize = 64;
pub const VOPRF_REQUEST_BYTES: usize = 40;
pub const VOPRF_EVALUATION_BYTES: usize = 136;

type CipherSuite = Ristretto255;
type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PhoneToken(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PairId(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OprfBlindRequest {
    pub epoch: u64,
    pub blinded_element: [u8; 32],
}

impl OprfBlindRequest {
    pub fn encode(&self) -> [u8; VOPRF_REQUEST_BYTES] {
        let mut encoded = [0; VOPRF_REQUEST_BYTES];
        encoded[..8].copy_from_slice(&self.epoch.to_be_bytes());
        encoded[8..].copy_from_slice(&self.blinded_element);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != VOPRF_REQUEST_BYTES {
            return Err(PhoneProtocolError::InvalidLength);
        }
        let request = Self {
            epoch: u64::from_be_bytes(fixed(&encoded[..8])?),
            blinded_element: fixed(&encoded[8..])?,
        };
        BlindedElement::<CipherSuite>::deserialize(&request.blinded_element)
            .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OprfEvaluation {
    pub epoch: u64,
    pub server_public_key: [u8; 32],
    pub evaluated_element: [u8; 32],
    pub proof: [u8; 64],
}

impl OprfEvaluation {
    pub fn encode(&self) -> [u8; VOPRF_EVALUATION_BYTES] {
        let mut encoded = [0; VOPRF_EVALUATION_BYTES];
        encoded[..8].copy_from_slice(&self.epoch.to_be_bytes());
        encoded[8..40].copy_from_slice(&self.server_public_key);
        encoded[40..72].copy_from_slice(&self.evaluated_element);
        encoded[72..].copy_from_slice(&self.proof);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != VOPRF_EVALUATION_BYTES {
            return Err(PhoneProtocolError::InvalidLength);
        }
        let evaluation = Self {
            epoch: u64::from_be_bytes(fixed(&encoded[..8])?),
            server_public_key: fixed(&encoded[8..40])?,
            evaluated_element: fixed(&encoded[40..72])?,
            proof: fixed(&encoded[72..])?,
        };
        <CipherSuite as voprf::CipherSuite>::Group::deserialize_elem(&evaluation.server_public_key)
            .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?;
        EvaluationElement::<CipherSuite>::deserialize(&evaluation.evaluated_element)
            .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?;
        Proof::<CipherSuite>::deserialize(&evaluation.proof)
            .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?;
        Ok(evaluation)
    }
}

pub struct OprfClientSession {
    epoch: u64,
    input: Vec<u8>,
    state: VoprfClient<CipherSuite>,
}

impl OprfClientSession {
    pub fn blind(e164: &str, epoch: u64) -> Result<(Self, OprfBlindRequest), PhoneProtocolError> {
        let normalized = normalize_e164(e164)?;
        let input = phone_input(&normalized, epoch);
        let result = VoprfClient::<CipherSuite>::blind(&input, &mut OsRng)
            .map_err(|_| PhoneProtocolError::Voprf)?;
        let serialized_message = result.message.serialize();
        let blinded_element = fixed(serialized_message.as_ref())?;
        Ok((
            Self {
                epoch,
                input,
                state: result.state,
            },
            OprfBlindRequest {
                epoch,
                blinded_element,
            },
        ))
    }

    pub fn finalize(
        self,
        evaluation: &OprfEvaluation,
        expected_public_key: [u8; 32],
    ) -> Result<[u8; 64], PhoneProtocolError> {
        if evaluation.epoch != self.epoch {
            return Err(PhoneProtocolError::EpochMismatch);
        }
        if evaluation.server_public_key != expected_public_key {
            return Err(PhoneProtocolError::UnexpectedServerKey);
        }
        let message = EvaluationElement::<CipherSuite>::deserialize(&evaluation.evaluated_element)
            .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?;
        let proof = Proof::<CipherSuite>::deserialize(&evaluation.proof)
            .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?;
        let public_key =
            <CipherSuite as voprf::CipherSuite>::Group::deserialize_elem(&expected_public_key)
                .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?;
        let output = self
            .state
            .finalize(&self.input, &message, &proof, public_key)
            .map_err(|_| PhoneProtocolError::VoprfProof)?;
        fixed(output.as_ref())
    }

    pub fn export_state(&self) -> [u8; VOPRF_CLIENT_STATE_BYTES] {
        fixed(self.state.serialize().as_ref()).expect("Ristretto255 VOPRF state is 64 bytes")
    }

    pub fn restore(
        e164: &str,
        epoch: u64,
        state: [u8; VOPRF_CLIENT_STATE_BYTES],
    ) -> Result<Self, PhoneProtocolError> {
        let normalized = normalize_e164(e164)?;
        Ok(Self {
            epoch,
            input: phone_input(&normalized, epoch),
            state: VoprfClient::<CipherSuite>::deserialize(&state)
                .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?,
        })
    }
}

#[derive(Clone)]
pub struct OprfServerKey {
    epoch: u64,
    server: VoprfServer<CipherSuite>,
}

impl OprfServerKey {
    pub fn from_seed(epoch: u64, seed: &[u8]) -> Result<Self, PhoneProtocolError> {
        if seed.len() < 32 {
            return Err(PhoneProtocolError::WeakKeyMaterial);
        }
        let mut info = b"TEX8/MFW/voprf-server/v1".to_vec();
        info.extend_from_slice(&epoch.to_be_bytes());
        let server = VoprfServer::<CipherSuite>::new_from_seed(seed, &info)
            .map_err(|_| PhoneProtocolError::Voprf)?;
        Ok(Self { epoch, server })
    }

    pub fn generate(epoch: u64) -> Result<Self, PhoneProtocolError> {
        let server =
            VoprfServer::<CipherSuite>::new(&mut OsRng).map_err(|_| PhoneProtocolError::Voprf)?;
        Ok(Self { epoch, server })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn public_key(&self) -> [u8; 32] {
        let serialized = <CipherSuite as voprf::CipherSuite>::Group::serialize_elem(
            self.server.get_public_key(),
        );
        fixed(serialized.as_ref()).expect("Ristretto255 public keys are 32 bytes")
    }

    pub fn evaluate(
        &self,
        request: &OprfBlindRequest,
    ) -> Result<OprfEvaluation, PhoneProtocolError> {
        if request.epoch != self.epoch {
            return Err(PhoneProtocolError::EpochMismatch);
        }
        let blinded = BlindedElement::<CipherSuite>::deserialize(&request.blinded_element)
            .map_err(|_| PhoneProtocolError::InvalidVoprfMessage)?;
        let result = self.server.blind_evaluate(&mut OsRng, &blinded);
        let serialized_message = result.message.serialize();
        let serialized_proof = result.proof.serialize();
        Ok(OprfEvaluation {
            epoch: self.epoch,
            server_public_key: self.public_key(),
            evaluated_element: fixed(serialized_message.as_ref())?,
            proof: fixed(serialized_proof.as_ref())?,
        })
    }
}

/// Combines exactly two independently verifiable VOPRF results. This is a
/// 2-of-2 multi-server composition: one node alone cannot derive the token.
pub fn combine_phone_token(
    first_public_key: [u8; 32],
    first_output: [u8; 64],
    second_public_key: [u8; 32],
    second_output: [u8; 64],
) -> Result<PhoneToken, PhoneProtocolError> {
    if first_public_key == second_public_key {
        return Err(PhoneProtocolError::DuplicateServer);
    }
    let mut values = [
        (first_public_key, first_output),
        (second_public_key, second_output),
    ];
    values.sort_by_key(|value| value.0);
    let mut digest = Sha256::new();
    digest.update(PHONE_TOKEN_DOMAIN);
    for (public_key, output) in values {
        digest.update(public_key);
        digest.update(output);
    }
    Ok(PhoneToken(digest.finalize().into()))
}

pub fn derive_pair_id(first: PhoneToken, second: PhoneToken) -> Result<PairId, PhoneProtocolError> {
    if first == second {
        return Err(PhoneProtocolError::SelfPair);
    }
    let mut tokens = [first, second];
    tokens.sort();
    let mut digest = Sha256::new();
    digest.update(PAIR_ID_DOMAIN);
    digest.update(tokens[0].0);
    digest.update(tokens[1].0);
    Ok(PairId(digest.finalize().into()))
}

pub fn normalize_e164(input: &str) -> Result<String, PhoneProtocolError> {
    if input.trim() != input || !input.starts_with('+') {
        return Err(PhoneProtocolError::InvalidPhoneNumber);
    }
    let digits = &input[1..];
    if !(8..=15).contains(&digits.len())
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PhoneProtocolError::InvalidPhoneNumber);
    }
    Ok(input.to_owned())
}

fn phone_input(normalized: &str, epoch: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(PHONE_INPUT_DOMAIN.len() + 8 + normalized.len());
    input.extend_from_slice(PHONE_INPUT_DOMAIN);
    input.extend_from_slice(&epoch.to_be_bytes());
    input.extend_from_slice(normalized.as_bytes());
    input
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ContactPolicy {
    BadgeOnly = 1,
    AskEveryTime = 2,
    DirectReceiveAddress = 3,
}

impl ContactPolicy {
    fn decode(value: u8) -> Result<Self, PhoneProtocolError> {
        match value {
            1 => Ok(Self::BadgeOnly),
            2 => Ok(Self::AskEveryTime),
            3 => Ok(Self::DirectReceiveAddress),
            _ => Err(PhoneProtocolError::InvalidPolicy),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactCard {
    pub policy: ContactPolicy,
    pub network: Network,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub publisher_token: PhoneToken,
    pub recipient_token: PhoneToken,
    pub address: Option<PublicAddress>,
}

impl ContactCard {
    pub fn validate(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_CONTACT_CARD_LIFETIME_SECONDS,
        )?;
        if self.publisher_token == self.recipient_token {
            return Err(PhoneProtocolError::SelfPair);
        }
        match (self.policy, self.address) {
            (ContactPolicy::DirectReceiveAddress, Some(address)) => address
                .validate()
                .map_err(|_| PhoneProtocolError::InvalidPublicKey),
            (ContactPolicy::DirectReceiveAddress, None) => {
                Err(PhoneProtocolError::MissingReceiveAddress)
            }
            (_, Some(_)) => Err(PhoneProtocolError::UnexpectedReceiveAddress),
            (_, None) => Ok(()),
        }
    }

    pub fn pair_id(&self) -> Result<PairId, PhoneProtocolError> {
        derive_pair_id(self.publisher_token, self.recipient_token)
    }

    pub fn encode_fixed(&self) -> Result<[u8; CONTACT_CARD_BYTES], PhoneProtocolError> {
        self.validate()?;
        let mut encoded = [0_u8; CONTACT_CARD_BYTES];
        encoded[..8].copy_from_slice(CARD_MAGIC);
        encoded[8] = VERSION;
        encoded[9] = self.policy as u8;
        encoded[10] = self.network as u8;
        encoded[11] = self.address.map_or(0xff, |address| address.kind as u8);
        encoded[12..20].copy_from_slice(&self.issued_at.to_be_bytes());
        encoded[20..28].copy_from_slice(&self.expires_at.to_be_bytes());
        encoded[28..36].copy_from_slice(&self.sequence.to_be_bytes());
        encoded[36..68].copy_from_slice(&self.publisher_token.0);
        encoded[68..100].copy_from_slice(&self.recipient_token.0);
        if let Some(address) = self.address {
            encoded[100..132].copy_from_slice(&address.public_spend_key);
            encoded[132..164].copy_from_slice(&address.public_view_key);
        }
        Ok(encoded)
    }

    pub fn decode_fixed(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != CONTACT_CARD_BYTES {
            return Err(PhoneProtocolError::InvalidLength);
        }
        if &encoded[..8] != CARD_MAGIC || encoded[8] != VERSION {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        if encoded[164..].iter().any(|byte| *byte != 0) {
            return Err(PhoneProtocolError::NonCanonical);
        }
        let policy = ContactPolicy::decode(encoded[9])?;
        let network = decode_network(encoded[10])?;
        let address = match encoded[11] {
            0xff => {
                if encoded[100..164].iter().any(|byte| *byte != 0) {
                    return Err(PhoneProtocolError::NonCanonical);
                }
                None
            }
            kind => Some(PublicAddress::new(
                decode_kind(kind)?,
                fixed(&encoded[100..132])?,
                fixed(&encoded[132..164])?,
            )?),
        };
        let card = Self {
            policy,
            network,
            issued_at: u64::from_be_bytes(fixed(&encoded[12..20])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[20..28])?),
            sequence: u64::from_be_bytes(fixed(&encoded[28..36])?),
            publisher_token: PhoneToken(fixed(&encoded[36..68])?),
            recipient_token: PhoneToken(fixed(&encoded[68..100])?),
            address,
        };
        card.validate()?;
        if card.encode_fixed()?.as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(card)
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ContactSigningKey([u8; 32]);

impl ContactSigningKey {
    pub fn generate() -> Result<Self, PhoneProtocolError> {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| PhoneProtocolError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }

    pub fn export_bytes(&self) -> [u8; 32] {
        self.0
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.0).sign(message).to_bytes()
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct HpkePrivateKey([u8; 32]);

impl HpkePrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn export_bytes(&self) -> [u8; 32] {
        self.0
    }
}

pub fn generate_hpke_keypair() -> Result<(HpkePrivateKey, [u8; 32]), PhoneProtocolError> {
    let (private, public) = Kem::gen_keypair();
    Ok((
        HpkePrivateKey(fixed(private.to_bytes().as_slice())?),
        fixed(public.to_bytes().as_slice())?,
    ))
}

pub fn derive_hpke_key_id(public_key: [u8; 32]) -> Result<[u8; 16], PhoneProtocolError> {
    <Kem as KemTrait>::PublicKey::from_bytes(&public_key)
        .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
    Ok(hpke_key_id(&public_key))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantRecord {
    pub epoch: u64,
    pub phone_token: PhoneToken,
    pub contact_signing_public_key: [u8; 32],
    pub hpke_public_key: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub verification_signature: [u8; 64],
}

impl ParticipantRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn authorized(
        epoch: u64,
        phone_token: PhoneToken,
        contact_signing_public_key: [u8; 32],
        hpke_public_key: [u8; 32],
        issued_at: u64,
        expires_at: u64,
        sequence: u64,
        verification_key: &ContactSigningKey,
    ) -> Result<Self, PhoneProtocolError> {
        let mut record = Self {
            epoch,
            phone_token,
            contact_signing_public_key,
            hpke_public_key,
            issued_at,
            expires_at,
            sequence,
            verification_signature: [0; 64],
        };
        record.validate_fields()?;
        record.verification_signature = verification_key.sign(&record.signing_message());
        Ok(record)
    }

    pub fn verify(
        &self,
        expected_verification_public_key: [u8; 32],
        now: u64,
    ) -> Result<(), PhoneProtocolError> {
        self.validate_fields()?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(PhoneProtocolError::Expired);
        }
        verify_signature(
            expected_verification_public_key,
            &self.signing_message(),
            self.verification_signature,
        )
    }

    pub fn hpke_key_id(&self) -> [u8; 16] {
        hpke_key_id(&self.hpke_public_key)
    }

    pub fn encode(&self) -> [u8; PARTICIPANT_RECORD_BYTES] {
        let unsigned = self.unsigned_bytes();
        let mut encoded = [0_u8; PARTICIPANT_RECORD_BYTES];
        encoded[..137].copy_from_slice(&unsigned);
        encoded[137..].copy_from_slice(&self.verification_signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != PARTICIPANT_RECORD_BYTES
            || &encoded[..8] != AUTH_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        let record = Self {
            epoch: u64::from_be_bytes(fixed(&encoded[9..17])?),
            phone_token: PhoneToken(fixed(&encoded[17..49])?),
            contact_signing_public_key: fixed(&encoded[49..81])?,
            hpke_public_key: fixed(&encoded[81..113])?,
            issued_at: u64::from_be_bytes(fixed(&encoded[113..121])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[121..129])?),
            sequence: u64::from_be_bytes(fixed(&encoded[129..137])?),
            verification_signature: fixed(&encoded[137..201])?,
        };
        record.validate_fields()?;
        if record.encode().as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(record)
    }

    fn validate_fields(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_PARTICIPANT_LIFETIME_SECONDS,
        )?;
        VerifyingKey::from_bytes(&self.contact_signing_public_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        <Kem as KemTrait>::PublicKey::from_bytes(&self.hpke_public_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        Ok(())
    }

    fn unsigned_bytes(&self) -> [u8; 137] {
        let mut encoded = [0_u8; 137];
        encoded[..8].copy_from_slice(AUTH_MAGIC);
        encoded[8] = VERSION;
        encoded[9..17].copy_from_slice(&self.epoch.to_be_bytes());
        encoded[17..49].copy_from_slice(&self.phone_token.0);
        encoded[49..81].copy_from_slice(&self.contact_signing_public_key);
        encoded[81..113].copy_from_slice(&self.hpke_public_key);
        encoded[113..121].copy_from_slice(&self.issued_at.to_be_bytes());
        encoded[121..129].copy_from_slice(&self.expires_at.to_be_bytes());
        encoded[129..137].copy_from_slice(&self.sequence.to_be_bytes());
        encoded
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message = AUTH_DOMAIN.to_vec();
        message.extend_from_slice(&self.unsigned_bytes());
        message
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermitRefreshRequest {
    pub epoch: u64,
    pub phone_token: PhoneToken,
    pub participant_sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

impl PermitRefreshRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        epoch: u64,
        phone_token: PhoneToken,
        participant_sequence: u64,
        issued_at: u64,
        expires_at: u64,
        nonce: [u8; 16],
        participant_signing_key: &ContactSigningKey,
    ) -> Result<Self, PhoneProtocolError> {
        let mut request = Self {
            epoch,
            phone_token,
            participant_sequence,
            issued_at,
            expires_at,
            nonce,
            signature: [0; 64],
        };
        request.validate_fields()?;
        request.signature = participant_signing_key.sign(&request.signing_message());
        Ok(request)
    }

    pub fn verify(
        &self,
        expected_epoch: u64,
        expected_participant_sequence: u64,
        expected_participant_public_key: [u8; 32],
        now: u64,
    ) -> Result<(), PhoneProtocolError> {
        self.validate_fields()?;
        if self.epoch != expected_epoch {
            return Err(PhoneProtocolError::EpochMismatch);
        }
        if self.participant_sequence != expected_participant_sequence {
            return Err(PhoneProtocolError::UnexpectedSequence);
        }
        if now < self.issued_at || now >= self.expires_at {
            return Err(PhoneProtocolError::Expired);
        }
        verify_signature(
            expected_participant_public_key,
            &self.signing_message(),
            self.signature,
        )
    }

    pub fn encode(&self) -> [u8; PERMIT_REFRESH_REQUEST_BYTES] {
        let unsigned = self.unsigned_bytes();
        let mut encoded = [0_u8; PERMIT_REFRESH_REQUEST_BYTES];
        encoded[..89].copy_from_slice(&unsigned);
        encoded[89..].copy_from_slice(&self.signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != PERMIT_REFRESH_REQUEST_BYTES
            || &encoded[..8] != PERMIT_REFRESH_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        let request = Self {
            epoch: u64::from_be_bytes(fixed(&encoded[9..17])?),
            phone_token: PhoneToken(fixed(&encoded[17..49])?),
            participant_sequence: u64::from_be_bytes(fixed(&encoded[49..57])?),
            issued_at: u64::from_be_bytes(fixed(&encoded[57..65])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[65..73])?),
            nonce: fixed(&encoded[73..89])?,
            signature: fixed(&encoded[89..153])?,
        };
        request.validate_fields()?;
        if request.encode().as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(request)
    }

    fn validate_fields(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_PERMIT_REFRESH_LIFETIME_SECONDS,
        )?;
        if self.participant_sequence == 0 {
            return Err(PhoneProtocolError::UnexpectedSequence);
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> [u8; 89] {
        let mut encoded = [0_u8; 89];
        encoded[..8].copy_from_slice(PERMIT_REFRESH_MAGIC);
        encoded[8] = VERSION;
        encoded[9..17].copy_from_slice(&self.epoch.to_be_bytes());
        encoded[17..49].copy_from_slice(&self.phone_token.0);
        encoded[49..57].copy_from_slice(&self.participant_sequence.to_be_bytes());
        encoded[57..65].copy_from_slice(&self.issued_at.to_be_bytes());
        encoded[65..73].copy_from_slice(&self.expires_at.to_be_bytes());
        encoded[73..89].copy_from_slice(&self.nonce);
        encoded
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message = PERMIT_REFRESH_DOMAIN.to_vec();
        message.extend_from_slice(&self.unsigned_bytes());
        message
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantRevocation {
    pub phone_token: PhoneToken,
    pub participant_signing_public_key: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub cooldown_until: u64,
    pub sequence: u64,
    pub signature: [u8; 64],
}

impl ParticipantRevocation {
    pub fn signed(
        phone_token: PhoneToken,
        issued_at: u64,
        expires_at: u64,
        cooldown_until: u64,
        sequence: u64,
        participant_signing_key: &ContactSigningKey,
    ) -> Result<Self, PhoneProtocolError> {
        let mut revocation = Self {
            phone_token,
            participant_signing_public_key: participant_signing_key.public_key(),
            issued_at,
            expires_at,
            cooldown_until,
            sequence,
            signature: [0; 64],
        };
        revocation.validate_fields()?;
        revocation.signature = participant_signing_key.sign(&revocation.signing_message());
        Ok(revocation)
    }

    pub fn verify(
        &self,
        expected_participant_public_key: [u8; 32],
        now: u64,
    ) -> Result<(), PhoneProtocolError> {
        self.validate_fields()?;
        if self.participant_signing_public_key != expected_participant_public_key {
            return Err(PhoneProtocolError::UnexpectedPublisher);
        }
        if now < self.issued_at || now >= self.expires_at {
            return Err(PhoneProtocolError::Expired);
        }
        verify_signature(
            expected_participant_public_key,
            &self.signing_message(),
            self.signature,
        )
    }

    pub fn encode(&self) -> [u8; PARTICIPANT_REVOCATION_BYTES] {
        let unsigned = self.unsigned_bytes();
        let mut encoded = [0_u8; PARTICIPANT_REVOCATION_BYTES];
        encoded[..105].copy_from_slice(&unsigned);
        encoded[105..].copy_from_slice(&self.signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != PARTICIPANT_REVOCATION_BYTES
            || &encoded[..8] != PARTICIPANT_REVOCATION_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        let revocation = Self {
            phone_token: PhoneToken(fixed(&encoded[9..41])?),
            participant_signing_public_key: fixed(&encoded[41..73])?,
            issued_at: u64::from_be_bytes(fixed(&encoded[73..81])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[81..89])?),
            cooldown_until: u64::from_be_bytes(fixed(&encoded[89..97])?),
            sequence: u64::from_be_bytes(fixed(&encoded[97..105])?),
            signature: fixed(&encoded[105..169])?,
        };
        revocation.validate_fields()?;
        if revocation.encode().as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(revocation)
    }

    fn validate_fields(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_PARTICIPANT_LIFETIME_SECONDS,
        )?;
        if self.cooldown_until < self.issued_at
            || self.cooldown_until
                > self
                    .issued_at
                    .checked_add(MAX_NUMBER_REASSIGNMENT_COOLDOWN_SECONDS)
                    .ok_or(PhoneProtocolError::Overflow)?
        {
            return Err(PhoneProtocolError::InvalidCooldown);
        }
        VerifyingKey::from_bytes(&self.participant_signing_public_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        Ok(())
    }

    fn unsigned_bytes(&self) -> [u8; 105] {
        let mut encoded = [0_u8; 105];
        encoded[..8].copy_from_slice(PARTICIPANT_REVOCATION_MAGIC);
        encoded[8] = VERSION;
        encoded[9..41].copy_from_slice(&self.phone_token.0);
        encoded[41..73].copy_from_slice(&self.participant_signing_public_key);
        encoded[73..81].copy_from_slice(&self.issued_at.to_be_bytes());
        encoded[81..89].copy_from_slice(&self.expires_at.to_be_bytes());
        encoded[89..97].copy_from_slice(&self.cooldown_until.to_be_bytes());
        encoded[97..105].copy_from_slice(&self.sequence.to_be_bytes());
        encoded
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message = PARTICIPANT_REVOCATION_DOMAIN.to_vec();
        message.extend_from_slice(&self.unsigned_bytes());
        message
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactEnvelope {
    pub pair_id: PairId,
    pub publisher_token: PhoneToken,
    pub publisher_signing_public_key: [u8; 32],
    pub recipient_hpke_key_id: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub encapsulated_key: [u8; 32],
    pub ciphertext: [u8; CONTACT_CIPHERTEXT_BYTES],
    pub signature: [u8; 64],
}

impl ContactEnvelope {
    pub fn seal(
        card: &ContactCard,
        publisher_signing_key: &ContactSigningKey,
        recipient_hpke_public_key: [u8; 32],
    ) -> Result<Self, PhoneProtocolError> {
        card.validate()?;
        let recipient = <Kem as KemTrait>::PublicKey::from_bytes(&recipient_hpke_public_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        let mut envelope = Self {
            pair_id: card.pair_id()?,
            publisher_token: card.publisher_token,
            publisher_signing_public_key: publisher_signing_key.public_key(),
            recipient_hpke_key_id: hpke_key_id(&recipient_hpke_public_key),
            issued_at: card.issued_at,
            expires_at: card.expires_at,
            sequence: card.sequence,
            encapsulated_key: [0; 32],
            ciphertext: [0; CONTACT_CIPHERTEXT_BYTES],
            signature: [0; 64],
        };
        let (encapsulated, mut context) =
            hpke::setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &recipient, HPKE_INFO)
                .map_err(|_| PhoneProtocolError::Hpke)?;
        envelope.encapsulated_key = fixed(encapsulated.to_bytes().as_slice())?;
        let aad = envelope.aad();
        let mut plaintext = card.encode_fixed()?;
        let encrypted = context
            .seal(&plaintext, &aad)
            .map_err(|_| PhoneProtocolError::Hpke);
        plaintext.zeroize();
        envelope.ciphertext = fixed(&encrypted?)?;
        envelope.signature = publisher_signing_key.sign(&envelope.signing_message());
        Ok(envelope)
    }

    pub fn verify(
        &self,
        expected_publisher_public_key: [u8; 32],
        now: u64,
    ) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_CONTACT_CARD_LIFETIME_SECONDS,
        )?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(PhoneProtocolError::Expired);
        }
        if self.publisher_signing_public_key != expected_publisher_public_key {
            return Err(PhoneProtocolError::UnexpectedPublisher);
        }
        verify_signature(
            expected_publisher_public_key,
            &self.signing_message(),
            self.signature,
        )
    }

    pub fn open(
        &self,
        expected_publisher_public_key: [u8; 32],
        recipient_private_key: &HpkePrivateKey,
        recipient_public_key: [u8; 32],
        now: u64,
    ) -> Result<ContactCard, PhoneProtocolError> {
        self.verify(expected_publisher_public_key, now)?;
        if hpke_key_id(&recipient_public_key) != self.recipient_hpke_key_id {
            return Err(PhoneProtocolError::WrongRecipient);
        }
        let private = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private_key.0)
            .map_err(|_| PhoneProtocolError::InvalidPrivateKey)?;
        let encapsulated = <Kem as KemTrait>::EncappedKey::from_bytes(&self.encapsulated_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        let mut context = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private,
            &encapsulated,
            HPKE_INFO,
        )
        .map_err(|_| PhoneProtocolError::Hpke)?;
        let mut plaintext = context
            .open(&self.ciphertext, &self.aad())
            .map_err(|_| PhoneProtocolError::Hpke)?;
        let card = ContactCard::decode_fixed(&plaintext);
        plaintext.zeroize();
        let card = card?;
        if card.pair_id()? != self.pair_id
            || card.publisher_token != self.publisher_token
            || card.issued_at != self.issued_at
            || card.expires_at != self.expires_at
            || card.sequence != self.sequence
        {
            return Err(PhoneProtocolError::EnvelopeBinding);
        }
        Ok(card)
    }

    pub fn encode(&self) -> [u8; CONTACT_ENVELOPE_BYTES] {
        let mut encoded = [0_u8; CONTACT_ENVELOPE_BYTES];
        encoded[..169].copy_from_slice(&self.aad());
        encoded[169..201].copy_from_slice(&self.encapsulated_key);
        encoded[201..473].copy_from_slice(&self.ciphertext);
        encoded[473..537].copy_from_slice(&self.signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != CONTACT_ENVELOPE_BYTES
            || &encoded[..8] != ENVELOPE_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        let envelope = Self {
            pair_id: PairId(fixed(&encoded[9..41])?),
            publisher_token: PhoneToken(fixed(&encoded[41..73])?),
            publisher_signing_public_key: fixed(&encoded[73..105])?,
            recipient_hpke_key_id: fixed(&encoded[105..121])?,
            issued_at: u64::from_be_bytes(fixed(&encoded[121..129])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[129..137])?),
            sequence: u64::from_be_bytes(fixed(&encoded[137..145])?),
            encapsulated_key: fixed(&encoded[169..201])?,
            ciphertext: fixed(&encoded[201..473])?,
            signature: fixed(&encoded[473..537])?,
        };
        if encoded[145..169].iter().any(|byte| *byte != 0) {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(envelope)
    }

    fn aad(&self) -> [u8; 169] {
        let mut aad = [0_u8; 169];
        aad[..8].copy_from_slice(ENVELOPE_MAGIC);
        aad[8] = VERSION;
        aad[9..41].copy_from_slice(&self.pair_id.0);
        aad[41..73].copy_from_slice(&self.publisher_token.0);
        aad[73..105].copy_from_slice(&self.publisher_signing_public_key);
        aad[105..121].copy_from_slice(&self.recipient_hpke_key_id);
        aad[121..129].copy_from_slice(&self.issued_at.to_be_bytes());
        aad[129..137].copy_from_slice(&self.expires_at.to_be_bytes());
        aad[137..145].copy_from_slice(&self.sequence.to_be_bytes());
        aad
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message =
            Vec::with_capacity(ENVELOPE_SIGNATURE_DOMAIN.len() + CONTACT_ENVELOPE_BYTES - 64);
        message.extend_from_slice(ENVELOPE_SIGNATURE_DOMAIN);
        message.extend_from_slice(&self.aad());
        message.extend_from_slice(&self.encapsulated_key);
        message.extend_from_slice(&self.ciphertext);
        message
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AskMessageKind {
    Request = 1,
    Response = 2,
}

impl AskMessageKind {
    fn decode(value: u8) -> Result<Self, PhoneProtocolError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            _ => Err(PhoneProtocolError::InvalidAskMessage),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AskDecision {
    Declined = 1,
    Approved = 2,
}

impl AskDecision {
    fn decode(value: u8) -> Result<Self, PhoneProtocolError> {
        match value {
            1 => Ok(Self::Declined),
            2 => Ok(Self::Approved),
            _ => Err(PhoneProtocolError::InvalidAskMessage),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AskRequest {
    pub network: Network,
    pub pair_id: PairId,
    pub request_id: [u8; 32],
    pub requester_token: PhoneToken,
    pub target_token: PhoneToken,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
}

impl AskRequest {
    pub fn validate(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_ASK_MESSAGE_LIFETIME_SECONDS,
        )?;
        if self.request_id == [0; 32] || self.sequence == 0 {
            return Err(PhoneProtocolError::InvalidAskMessage);
        }
        if derive_pair_id(self.requester_token, self.target_token)? != self.pair_id {
            return Err(PhoneProtocolError::EnvelopeBinding);
        }
        Ok(())
    }

    pub fn encode_fixed(&self) -> Result<[u8; ASK_MESSAGE_BYTES], PhoneProtocolError> {
        self.validate()?;
        let mut encoded = [0_u8; ASK_MESSAGE_BYTES];
        encoded[..8].copy_from_slice(ASK_REQUEST_MAGIC);
        encoded[8] = VERSION;
        encoded[9] = self.network as u8;
        encoded[16..48].copy_from_slice(&self.pair_id.0);
        encoded[48..80].copy_from_slice(&self.request_id);
        encoded[80..112].copy_from_slice(&self.requester_token.0);
        encoded[112..144].copy_from_slice(&self.target_token.0);
        encoded[144..152].copy_from_slice(&self.issued_at.to_be_bytes());
        encoded[152..160].copy_from_slice(&self.expires_at.to_be_bytes());
        encoded[160..168].copy_from_slice(&self.sequence.to_be_bytes());
        Ok(encoded)
    }

    pub fn decode_fixed(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != ASK_MESSAGE_BYTES
            || &encoded[..8] != ASK_REQUEST_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        if encoded[10..16].iter().any(|byte| *byte != 0)
            || encoded[168..].iter().any(|byte| *byte != 0)
        {
            return Err(PhoneProtocolError::NonCanonical);
        }
        let request = Self {
            network: decode_network(encoded[9])?,
            pair_id: PairId(fixed(&encoded[16..48])?),
            request_id: fixed(&encoded[48..80])?,
            requester_token: PhoneToken(fixed(&encoded[80..112])?),
            target_token: PhoneToken(fixed(&encoded[112..144])?),
            issued_at: u64::from_be_bytes(fixed(&encoded[144..152])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[152..160])?),
            sequence: u64::from_be_bytes(fixed(&encoded[160..168])?),
        };
        request.validate()?;
        if request.encode_fixed()?.as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AskResponse {
    pub decision: AskDecision,
    pub network: Network,
    pub pair_id: PairId,
    pub request_id: [u8; 32],
    pub responder_token: PhoneToken,
    pub requester_token: PhoneToken,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub address: Option<PublicAddress>,
}

impl AskResponse {
    pub fn validate(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_ASK_MESSAGE_LIFETIME_SECONDS,
        )?;
        if self.request_id == [0; 32] || self.sequence == 0 {
            return Err(PhoneProtocolError::InvalidAskMessage);
        }
        if derive_pair_id(self.responder_token, self.requester_token)? != self.pair_id {
            return Err(PhoneProtocolError::EnvelopeBinding);
        }
        match (self.decision, self.address) {
            (AskDecision::Declined, None) => Ok(()),
            (AskDecision::Approved, Some(address)) if address.kind == AddressKind::Subaddress => {
                address
                    .validate()
                    .map_err(|_| PhoneProtocolError::InvalidPublicKey)
            }
            (AskDecision::Approved, Some(_)) => Err(PhoneProtocolError::InvalidAddressKind),
            (AskDecision::Approved, None) => Err(PhoneProtocolError::MissingReceiveAddress),
            (AskDecision::Declined, Some(_)) => Err(PhoneProtocolError::UnexpectedReceiveAddress),
        }
    }

    pub fn encode_fixed(&self) -> Result<[u8; ASK_MESSAGE_BYTES], PhoneProtocolError> {
        self.validate()?;
        let mut encoded = [0_u8; ASK_MESSAGE_BYTES];
        encoded[..8].copy_from_slice(ASK_RESPONSE_MAGIC);
        encoded[8] = VERSION;
        encoded[9] = self.decision as u8;
        encoded[10] = self.network as u8;
        encoded[11] = self.address.map_or(0xff, |address| address.kind as u8);
        encoded[16..48].copy_from_slice(&self.pair_id.0);
        encoded[48..80].copy_from_slice(&self.request_id);
        encoded[80..112].copy_from_slice(&self.responder_token.0);
        encoded[112..144].copy_from_slice(&self.requester_token.0);
        encoded[144..152].copy_from_slice(&self.issued_at.to_be_bytes());
        encoded[152..160].copy_from_slice(&self.expires_at.to_be_bytes());
        encoded[160..168].copy_from_slice(&self.sequence.to_be_bytes());
        if let Some(address) = self.address {
            encoded[168..200].copy_from_slice(&address.public_spend_key);
            encoded[200..232].copy_from_slice(&address.public_view_key);
        }
        Ok(encoded)
    }

    pub fn decode_fixed(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != ASK_MESSAGE_BYTES
            || &encoded[..8] != ASK_RESPONSE_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        if encoded[12..16].iter().any(|byte| *byte != 0)
            || encoded[232..].iter().any(|byte| *byte != 0)
        {
            return Err(PhoneProtocolError::NonCanonical);
        }
        let address = match encoded[11] {
            0xff => {
                if encoded[168..232].iter().any(|byte| *byte != 0) {
                    return Err(PhoneProtocolError::NonCanonical);
                }
                None
            }
            kind => Some(PublicAddress::new(
                decode_kind(kind)?,
                fixed(&encoded[168..200])?,
                fixed(&encoded[200..232])?,
            )?),
        };
        let response = Self {
            decision: AskDecision::decode(encoded[9])?,
            network: decode_network(encoded[10])?,
            pair_id: PairId(fixed(&encoded[16..48])?),
            request_id: fixed(&encoded[48..80])?,
            responder_token: PhoneToken(fixed(&encoded[80..112])?),
            requester_token: PhoneToken(fixed(&encoded[112..144])?),
            issued_at: u64::from_be_bytes(fixed(&encoded[144..152])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[152..160])?),
            sequence: u64::from_be_bytes(fixed(&encoded[160..168])?),
            address,
        };
        response.validate()?;
        if response.encode_fixed()?.as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AskEnvelope {
    pub kind: AskMessageKind,
    pub pair_id: PairId,
    pub request_id: [u8; 32],
    pub sender_token: PhoneToken,
    pub recipient_token: PhoneToken,
    pub sender_signing_public_key: [u8; 32],
    pub recipient_hpke_key_id: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub encapsulated_key: [u8; 32],
    pub ciphertext: [u8; ASK_CIPHERTEXT_BYTES],
    pub signature: [u8; 64],
}

impl AskEnvelope {
    pub fn seal_request(
        request: &AskRequest,
        requester_signing_key: &ContactSigningKey,
        target_hpke_public_key: [u8; 32],
    ) -> Result<Self, PhoneProtocolError> {
        request.validate()?;
        Self::seal(
            AskMessageKind::Request,
            request.pair_id,
            request.request_id,
            request.requester_token,
            request.target_token,
            request.issued_at,
            request.expires_at,
            request.sequence,
            request.encode_fixed()?,
            requester_signing_key,
            target_hpke_public_key,
        )
    }

    pub fn seal_response(
        response: &AskResponse,
        responder_signing_key: &ContactSigningKey,
        requester_hpke_public_key: [u8; 32],
    ) -> Result<Self, PhoneProtocolError> {
        response.validate()?;
        Self::seal(
            AskMessageKind::Response,
            response.pair_id,
            response.request_id,
            response.responder_token,
            response.requester_token,
            response.issued_at,
            response.expires_at,
            response.sequence,
            response.encode_fixed()?,
            responder_signing_key,
            requester_hpke_public_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn seal(
        kind: AskMessageKind,
        pair_id: PairId,
        request_id: [u8; 32],
        sender_token: PhoneToken,
        recipient_token: PhoneToken,
        issued_at: u64,
        expires_at: u64,
        sequence: u64,
        mut plaintext: [u8; ASK_MESSAGE_BYTES],
        sender_signing_key: &ContactSigningKey,
        recipient_hpke_public_key: [u8; 32],
    ) -> Result<Self, PhoneProtocolError> {
        let recipient = <Kem as KemTrait>::PublicKey::from_bytes(&recipient_hpke_public_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        let mut envelope = Self {
            kind,
            pair_id,
            request_id,
            sender_token,
            recipient_token,
            sender_signing_public_key: sender_signing_key.public_key(),
            recipient_hpke_key_id: hpke_key_id(&recipient_hpke_public_key),
            issued_at,
            expires_at,
            sequence,
            encapsulated_key: [0; 32],
            ciphertext: [0; ASK_CIPHERTEXT_BYTES],
            signature: [0; 64],
        };
        envelope.validate_fields()?;
        let (encapsulated, mut context) =
            hpke::setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &recipient, ASK_HPKE_INFO)
                .map_err(|_| PhoneProtocolError::Hpke)?;
        envelope.encapsulated_key = fixed(encapsulated.to_bytes().as_slice())?;
        let encrypted = context
            .seal(&plaintext, &envelope.aad())
            .map_err(|_| PhoneProtocolError::Hpke);
        plaintext.zeroize();
        envelope.ciphertext = fixed(&encrypted?)?;
        envelope.signature = sender_signing_key.sign(&envelope.signing_message());
        Ok(envelope)
    }

    pub fn verify(
        &self,
        expected_sender_public_key: [u8; 32],
        now: u64,
    ) -> Result<(), PhoneProtocolError> {
        self.validate_fields()?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(PhoneProtocolError::Expired);
        }
        if self.sender_signing_public_key != expected_sender_public_key {
            return Err(PhoneProtocolError::UnexpectedPublisher);
        }
        verify_signature(
            expected_sender_public_key,
            &self.signing_message(),
            self.signature,
        )
    }

    pub fn open_request(
        &self,
        expected_requester_public_key: [u8; 32],
        target_private_key: &HpkePrivateKey,
        target_public_key: [u8; 32],
        now: u64,
    ) -> Result<AskRequest, PhoneProtocolError> {
        if self.kind != AskMessageKind::Request {
            return Err(PhoneProtocolError::InvalidAskMessage);
        }
        let plaintext = self.open(
            expected_requester_public_key,
            target_private_key,
            target_public_key,
            now,
        )?;
        let request = AskRequest::decode_fixed(&plaintext);
        let request = request?;
        if request.pair_id != self.pair_id
            || request.request_id != self.request_id
            || request.requester_token != self.sender_token
            || request.target_token != self.recipient_token
            || request.issued_at != self.issued_at
            || request.expires_at != self.expires_at
            || request.sequence != self.sequence
        {
            return Err(PhoneProtocolError::EnvelopeBinding);
        }
        Ok(request)
    }

    pub fn open_response(
        &self,
        expected_responder_public_key: [u8; 32],
        requester_private_key: &HpkePrivateKey,
        requester_public_key: [u8; 32],
        now: u64,
    ) -> Result<AskResponse, PhoneProtocolError> {
        if self.kind != AskMessageKind::Response {
            return Err(PhoneProtocolError::InvalidAskMessage);
        }
        let plaintext = self.open(
            expected_responder_public_key,
            requester_private_key,
            requester_public_key,
            now,
        )?;
        let response = AskResponse::decode_fixed(&plaintext);
        let response = response?;
        if response.pair_id != self.pair_id
            || response.request_id != self.request_id
            || response.responder_token != self.sender_token
            || response.requester_token != self.recipient_token
            || response.issued_at != self.issued_at
            || response.expires_at != self.expires_at
            || response.sequence != self.sequence
        {
            return Err(PhoneProtocolError::EnvelopeBinding);
        }
        Ok(response)
    }

    fn open(
        &self,
        expected_sender_public_key: [u8; 32],
        recipient_private_key: &HpkePrivateKey,
        recipient_public_key: [u8; 32],
        now: u64,
    ) -> Result<[u8; ASK_MESSAGE_BYTES], PhoneProtocolError> {
        self.verify(expected_sender_public_key, now)?;
        if hpke_key_id(&recipient_public_key) != self.recipient_hpke_key_id {
            return Err(PhoneProtocolError::WrongRecipient);
        }
        let private = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private_key.0)
            .map_err(|_| PhoneProtocolError::InvalidPrivateKey)?;
        let encapsulated = <Kem as KemTrait>::EncappedKey::from_bytes(&self.encapsulated_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        let mut context = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private,
            &encapsulated,
            ASK_HPKE_INFO,
        )
        .map_err(|_| PhoneProtocolError::Hpke)?;
        let mut plaintext = context
            .open(&self.ciphertext, &self.aad())
            .map_err(|_| PhoneProtocolError::Hpke)?;
        let fixed_plaintext = fixed(&plaintext);
        plaintext.zeroize();
        fixed_plaintext
    }

    pub fn message_id(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(ASK_MESSAGE_ID_DOMAIN);
        digest.update(self.encode());
        digest.finalize().into()
    }

    pub fn encode(&self) -> [u8; ASK_ENVELOPE_BYTES] {
        let mut encoded = [0_u8; ASK_ENVELOPE_BYTES];
        encoded[..224].copy_from_slice(&self.aad());
        encoded[224..256].copy_from_slice(&self.encapsulated_key);
        encoded[256..528].copy_from_slice(&self.ciphertext);
        encoded[528..592].copy_from_slice(&self.signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != ASK_ENVELOPE_BYTES
            || &encoded[..8] != ASK_ENVELOPE_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        if encoded[210..224].iter().any(|byte| *byte != 0) {
            return Err(PhoneProtocolError::NonCanonical);
        }
        let envelope = Self {
            kind: AskMessageKind::decode(encoded[9])?,
            pair_id: PairId(fixed(&encoded[10..42])?),
            request_id: fixed(&encoded[42..74])?,
            sender_token: PhoneToken(fixed(&encoded[74..106])?),
            recipient_token: PhoneToken(fixed(&encoded[106..138])?),
            sender_signing_public_key: fixed(&encoded[138..170])?,
            recipient_hpke_key_id: fixed(&encoded[170..186])?,
            issued_at: u64::from_be_bytes(fixed(&encoded[186..194])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[194..202])?),
            sequence: u64::from_be_bytes(fixed(&encoded[202..210])?),
            encapsulated_key: fixed(&encoded[224..256])?,
            ciphertext: fixed(&encoded[256..528])?,
            signature: fixed(&encoded[528..592])?,
        };
        envelope.validate_fields()?;
        if envelope.encode().as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(envelope)
    }

    fn validate_fields(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_ASK_MESSAGE_LIFETIME_SECONDS,
        )?;
        if self.request_id == [0; 32] || self.sequence == 0 {
            return Err(PhoneProtocolError::InvalidAskMessage);
        }
        if derive_pair_id(self.sender_token, self.recipient_token)? != self.pair_id {
            return Err(PhoneProtocolError::EnvelopeBinding);
        }
        VerifyingKey::from_bytes(&self.sender_signing_public_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        Ok(())
    }

    fn aad(&self) -> [u8; 224] {
        let mut aad = [0_u8; 224];
        aad[..8].copy_from_slice(ASK_ENVELOPE_MAGIC);
        aad[8] = VERSION;
        aad[9] = self.kind as u8;
        aad[10..42].copy_from_slice(&self.pair_id.0);
        aad[42..74].copy_from_slice(&self.request_id);
        aad[74..106].copy_from_slice(&self.sender_token.0);
        aad[106..138].copy_from_slice(&self.recipient_token.0);
        aad[138..170].copy_from_slice(&self.sender_signing_public_key);
        aad[170..186].copy_from_slice(&self.recipient_hpke_key_id);
        aad[186..194].copy_from_slice(&self.issued_at.to_be_bytes());
        aad[194..202].copy_from_slice(&self.expires_at.to_be_bytes());
        aad[202..210].copy_from_slice(&self.sequence.to_be_bytes());
        aad
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message =
            Vec::with_capacity(ASK_ENVELOPE_SIGNATURE_DOMAIN.len() + ASK_ENVELOPE_BYTES - 64);
        message.extend_from_slice(ASK_ENVELOPE_SIGNATURE_DOMAIN);
        message.extend_from_slice(&self.aad());
        message.extend_from_slice(&self.encapsulated_key);
        message.extend_from_slice(&self.ciphertext);
        message
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AskMailboxPoll {
    pub kind: AskMessageKind,
    pub participant_token: PhoneToken,
    pub participant_sequence: u64,
    pub participant_hpke_key_id: [u8; 16],
    pub after_cursor: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

impl AskMailboxPoll {
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        kind: AskMessageKind,
        participant_token: PhoneToken,
        participant_sequence: u64,
        participant_hpke_key_id: [u8; 16],
        after_cursor: u64,
        issued_at: u64,
        expires_at: u64,
        nonce: [u8; 16],
        participant_signing_key: &ContactSigningKey,
    ) -> Result<Self, PhoneProtocolError> {
        let mut poll = Self {
            kind,
            participant_token,
            participant_sequence,
            participant_hpke_key_id,
            after_cursor,
            issued_at,
            expires_at,
            nonce,
            signature: [0; 64],
        };
        poll.validate_fields()?;
        poll.signature = participant_signing_key.sign(&poll.signing_message());
        Ok(poll)
    }

    pub fn verify(
        &self,
        expected_participant_sequence: u64,
        expected_participant_public_key: [u8; 32],
        expected_hpke_key_id: [u8; 16],
        now: u64,
    ) -> Result<(), PhoneProtocolError> {
        self.validate_fields()?;
        if self.participant_sequence != expected_participant_sequence {
            return Err(PhoneProtocolError::UnexpectedSequence);
        }
        if self.participant_hpke_key_id != expected_hpke_key_id {
            return Err(PhoneProtocolError::WrongRecipient);
        }
        if now < self.issued_at || now >= self.expires_at {
            return Err(PhoneProtocolError::Expired);
        }
        verify_signature(
            expected_participant_public_key,
            &self.signing_message(),
            self.signature,
        )
    }

    pub fn encode(&self) -> [u8; ASK_MAILBOX_POLL_BYTES] {
        let unsigned = self.unsigned_bytes();
        let mut encoded = [0_u8; ASK_MAILBOX_POLL_BYTES];
        encoded[..106].copy_from_slice(&unsigned);
        encoded[106..].copy_from_slice(&self.signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != ASK_MAILBOX_POLL_BYTES
            || &encoded[..8] != ASK_MAILBOX_POLL_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        let poll = Self {
            kind: AskMessageKind::decode(encoded[9])?,
            participant_token: PhoneToken(fixed(&encoded[10..42])?),
            participant_sequence: u64::from_be_bytes(fixed(&encoded[42..50])?),
            participant_hpke_key_id: fixed(&encoded[50..66])?,
            after_cursor: u64::from_be_bytes(fixed(&encoded[66..74])?),
            issued_at: u64::from_be_bytes(fixed(&encoded[74..82])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[82..90])?),
            nonce: fixed(&encoded[90..106])?,
            signature: fixed(&encoded[106..170])?,
        };
        poll.validate_fields()?;
        if poll.encode().as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(poll)
    }

    fn validate_fields(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_ASK_MAILBOX_POLL_LIFETIME_SECONDS,
        )?;
        if self.participant_sequence == 0 || self.nonce == [0; 16] {
            return Err(PhoneProtocolError::InvalidAskMessage);
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> [u8; 106] {
        let mut encoded = [0_u8; 106];
        encoded[..8].copy_from_slice(ASK_MAILBOX_POLL_MAGIC);
        encoded[8] = VERSION;
        encoded[9] = self.kind as u8;
        encoded[10..42].copy_from_slice(&self.participant_token.0);
        encoded[42..50].copy_from_slice(&self.participant_sequence.to_be_bytes());
        encoded[50..66].copy_from_slice(&self.participant_hpke_key_id);
        encoded[66..74].copy_from_slice(&self.after_cursor.to_be_bytes());
        encoded[74..82].copy_from_slice(&self.issued_at.to_be_bytes());
        encoded[82..90].copy_from_slice(&self.expires_at.to_be_bytes());
        encoded[90..106].copy_from_slice(&self.nonce);
        encoded
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message = ASK_MAILBOX_POLL_DOMAIN.to_vec();
        message.extend_from_slice(&self.unsigned_bytes());
        message
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactRevocation {
    pub pair_id: PairId,
    pub publisher_token: PhoneToken,
    pub publisher_signing_public_key: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub sequence: u64,
    pub signature: [u8; 64],
}

impl ContactRevocation {
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        pair_id: PairId,
        publisher_token: PhoneToken,
        issued_at: u64,
        expires_at: u64,
        sequence: u64,
        publisher_signing_key: &ContactSigningKey,
    ) -> Result<Self, PhoneProtocolError> {
        let mut revocation = Self {
            pair_id,
            publisher_token,
            publisher_signing_public_key: publisher_signing_key.public_key(),
            issued_at,
            expires_at,
            sequence,
            signature: [0; 64],
        };
        revocation.validate_fields()?;
        revocation.signature = publisher_signing_key.sign(&revocation.signing_message());
        Ok(revocation)
    }

    pub fn verify(
        &self,
        expected_publisher_public_key: [u8; 32],
        now: u64,
    ) -> Result<(), PhoneProtocolError> {
        self.validate_fields()?;
        if self.publisher_signing_public_key != expected_publisher_public_key {
            return Err(PhoneProtocolError::UnexpectedPublisher);
        }
        if now < self.issued_at || now >= self.expires_at {
            return Err(PhoneProtocolError::Expired);
        }
        verify_signature(
            expected_publisher_public_key,
            &self.signing_message(),
            self.signature,
        )
    }

    pub fn encode(&self) -> [u8; CONTACT_REVOCATION_BYTES] {
        let unsigned = self.unsigned_bytes();
        let mut encoded = [0_u8; CONTACT_REVOCATION_BYTES];
        encoded[..129].copy_from_slice(&unsigned);
        encoded[129..].copy_from_slice(&self.signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        if encoded.len() != CONTACT_REVOCATION_BYTES
            || &encoded[..8] != CONTACT_REVOCATION_MAGIC
            || encoded[8] != VERSION
        {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        let revocation = Self {
            pair_id: PairId(fixed(&encoded[9..41])?),
            publisher_token: PhoneToken(fixed(&encoded[41..73])?),
            publisher_signing_public_key: fixed(&encoded[73..105])?,
            issued_at: u64::from_be_bytes(fixed(&encoded[105..113])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[113..121])?),
            sequence: u64::from_be_bytes(fixed(&encoded[121..129])?),
            signature: fixed(&encoded[129..193])?,
        };
        revocation.validate_fields()?;
        if revocation.encode().as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(revocation)
    }

    fn validate_fields(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_CONTACT_CARD_LIFETIME_SECONDS,
        )?;
        VerifyingKey::from_bytes(&self.publisher_signing_public_key)
            .map_err(|_| PhoneProtocolError::InvalidPublicKey)?;
        Ok(())
    }

    fn unsigned_bytes(&self) -> [u8; 129] {
        let mut encoded = [0_u8; 129];
        encoded[..8].copy_from_slice(CONTACT_REVOCATION_MAGIC);
        encoded[8] = VERSION;
        encoded[9..41].copy_from_slice(&self.pair_id.0);
        encoded[41..73].copy_from_slice(&self.publisher_token.0);
        encoded[73..105].copy_from_slice(&self.publisher_signing_public_key);
        encoded[105..113].copy_from_slice(&self.issued_at.to_be_bytes());
        encoded[113..121].copy_from_slice(&self.expires_at.to_be_bytes());
        encoded[121..129].copy_from_slice(&self.sequence.to_be_bytes());
        encoded
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message = CONTACT_REVOCATION_DOMAIN.to_vec();
        message.extend_from_slice(&self.unsigned_bytes());
        message
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub envelope: ContactEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedDirectorySnapshot {
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub participants: Vec<ParticipantRecord>,
    pub entries: Vec<DirectoryEntry>,
    pub signing_public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl SignedDirectorySnapshot {
    pub fn signed(
        generation: u64,
        issued_at: u64,
        expires_at: u64,
        mut participants: Vec<ParticipantRecord>,
        mut entries: Vec<DirectoryEntry>,
        directory_signing_key: &ContactSigningKey,
    ) -> Result<Self, PhoneProtocolError> {
        participants.sort_by_key(|record| (record.phone_token, record.sequence));
        entries.sort_by_key(|entry| {
            (
                entry.envelope.pair_id,
                entry.envelope.publisher_token,
                entry.envelope.sequence,
            )
        });
        let mut snapshot = Self {
            generation,
            issued_at,
            expires_at,
            participants,
            entries,
            signing_public_key: directory_signing_key.public_key(),
            signature: [0; 64],
        };
        snapshot.validate_shape()?;
        snapshot.signature = directory_signing_key.sign(&snapshot.signing_message()?);
        Ok(snapshot)
    }

    pub fn verify(
        &self,
        expected_directory_public_key: [u8; 32],
        expected_verification_public_key: [u8; 32],
        now: u64,
    ) -> Result<(), PhoneProtocolError> {
        self.validate_shape()?;
        if self.signing_public_key != expected_directory_public_key {
            return Err(PhoneProtocolError::UnexpectedDirectoryKey);
        }
        if now < self.issued_at || now >= self.expires_at {
            return Err(PhoneProtocolError::Expired);
        }
        verify_signature(
            expected_directory_public_key,
            &self.signing_message()?,
            self.signature,
        )?;
        for participant in &self.participants {
            participant.verify(expected_verification_public_key, now)?;
        }
        let participant_keys: BTreeSet<(PhoneToken, [u8; 32])> = self
            .participants
            .iter()
            .map(|participant| {
                (
                    participant.phone_token,
                    participant.contact_signing_public_key,
                )
            })
            .collect();
        let recipient_key_ids: BTreeSet<[u8; 16]> = self
            .participants
            .iter()
            .map(ParticipantRecord::hpke_key_id)
            .collect();
        for entry in &self.entries {
            if !participant_keys.contains(&(
                entry.envelope.publisher_token,
                entry.envelope.publisher_signing_public_key,
            )) {
                return Err(PhoneProtocolError::UnauthorizedPublisher);
            }
            if !recipient_key_ids.contains(&entry.envelope.recipient_hpke_key_id) {
                return Err(PhoneProtocolError::UnknownRecipientKey);
            }
            entry
                .envelope
                .verify(entry.envelope.publisher_signing_public_key, now)?;
        }
        Ok(())
    }

    pub fn find_participant(&self, token: PhoneToken) -> Option<&ParticipantRecord> {
        self.participants
            .iter()
            .rev()
            .find(|participant| participant.phone_token == token)
    }

    pub fn find_pair(&self, pair_id: PairId) -> impl Iterator<Item = &DirectoryEntry> {
        self.entries
            .iter()
            .filter(move |entry| entry.envelope.pair_id == pair_id)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PhoneProtocolError> {
        let unsigned = self.unsigned_bytes()?;
        let mut encoded = Vec::with_capacity(unsigned.len() + 64);
        encoded.extend_from_slice(&unsigned);
        encoded.extend_from_slice(&self.signature);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PhoneProtocolError> {
        const HEADER: usize = 8 + 1 + 8 + 8 + 8 + 4 + 4 + 32;
        if encoded.len() < HEADER + 64 || &encoded[..8] != SNAPSHOT_MAGIC || encoded[8] != VERSION {
            return Err(PhoneProtocolError::InvalidHeader);
        }
        let participant_count = u32::from_be_bytes(fixed(&encoded[33..37])?) as usize;
        let entry_count = u32::from_be_bytes(fixed(&encoded[37..41])?) as usize;
        if participant_count > MAX_SNAPSHOT_PARTICIPANTS || entry_count > MAX_SNAPSHOT_ENTRIES {
            return Err(PhoneProtocolError::Oversized);
        }
        let expected = HEADER
            .checked_add(
                participant_count
                    .checked_mul(PARTICIPANT_RECORD_BYTES)
                    .ok_or(PhoneProtocolError::Overflow)?,
            )
            .and_then(|length| length.checked_add(entry_count.checked_mul(CONTACT_ENVELOPE_BYTES)?))
            .and_then(|length| length.checked_add(64))
            .ok_or(PhoneProtocolError::Overflow)?;
        if expected > MAX_SNAPSHOT_BYTES {
            return Err(PhoneProtocolError::Oversized);
        }
        if encoded.len() != expected {
            return Err(PhoneProtocolError::InvalidLength);
        }
        let mut cursor = HEADER;
        let mut participants = Vec::with_capacity(participant_count);
        for _ in 0..participant_count {
            participants.push(ParticipantRecord::decode(
                &encoded[cursor..cursor + PARTICIPANT_RECORD_BYTES],
            )?);
            cursor += PARTICIPANT_RECORD_BYTES;
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(DirectoryEntry {
                envelope: ContactEnvelope::decode(
                    &encoded[cursor..cursor + CONTACT_ENVELOPE_BYTES],
                )?,
            });
            cursor += CONTACT_ENVELOPE_BYTES;
        }
        let snapshot = Self {
            generation: u64::from_be_bytes(fixed(&encoded[9..17])?),
            issued_at: u64::from_be_bytes(fixed(&encoded[17..25])?),
            expires_at: u64::from_be_bytes(fixed(&encoded[25..33])?),
            participants,
            entries,
            signing_public_key: fixed(&encoded[41..73])?,
            signature: fixed(&encoded[cursor..cursor + 64])?,
        };
        snapshot.validate_shape()?;
        if snapshot.encode()?.as_slice() != encoded {
            return Err(PhoneProtocolError::NonCanonical);
        }
        Ok(snapshot)
    }

    fn validate_shape(&self) -> Result<(), PhoneProtocolError> {
        validate_window(
            self.issued_at,
            self.expires_at,
            MAX_SNAPSHOT_LIFETIME_SECONDS,
        )?;
        if self.participants.len() > MAX_SNAPSHOT_PARTICIPANTS
            || self.entries.len() > MAX_SNAPSHOT_ENTRIES
        {
            return Err(PhoneProtocolError::Oversized);
        }
        let encoded_bytes = 8_usize
            .checked_add(1)
            .and_then(|length| length.checked_add(8 + 8 + 8 + 4 + 4 + 32))
            .and_then(|length| {
                length.checked_add(
                    self.participants
                        .len()
                        .checked_mul(PARTICIPANT_RECORD_BYTES)?,
                )
            })
            .and_then(|length| {
                length.checked_add(self.entries.len().checked_mul(CONTACT_ENVELOPE_BYTES)?)
            })
            .and_then(|length| length.checked_add(64))
            .ok_or(PhoneProtocolError::Overflow)?;
        if encoded_bytes > MAX_SNAPSHOT_BYTES {
            return Err(PhoneProtocolError::Oversized);
        }
        if !self
            .participants
            .windows(2)
            .all(|values| values[0].phone_token < values[1].phone_token)
            || !self.entries.windows(2).all(|values| {
                (
                    values[0].envelope.pair_id,
                    values[0].envelope.publisher_token,
                ) < (
                    values[1].envelope.pair_id,
                    values[1].envelope.publisher_token,
                )
            })
        {
            return Err(PhoneProtocolError::DuplicateOrUnsorted);
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, PhoneProtocolError> {
        self.validate_shape()?;
        let participant_count =
            u32::try_from(self.participants.len()).map_err(|_| PhoneProtocolError::Oversized)?;
        let entry_count =
            u32::try_from(self.entries.len()).map_err(|_| PhoneProtocolError::Oversized)?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(SNAPSHOT_MAGIC);
        encoded.push(VERSION);
        encoded.extend_from_slice(&self.generation.to_be_bytes());
        encoded.extend_from_slice(&self.issued_at.to_be_bytes());
        encoded.extend_from_slice(&self.expires_at.to_be_bytes());
        encoded.extend_from_slice(&participant_count.to_be_bytes());
        encoded.extend_from_slice(&entry_count.to_be_bytes());
        encoded.extend_from_slice(&self.signing_public_key);
        for participant in &self.participants {
            encoded.extend_from_slice(&participant.encode());
        }
        for entry in &self.entries {
            encoded.extend_from_slice(&entry.envelope.encode());
        }
        Ok(encoded)
    }

    fn signing_message(&self) -> Result<Vec<u8>, PhoneProtocolError> {
        let mut message = SNAPSHOT_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&self.unsigned_bytes()?);
        Ok(message)
    }
}

fn hpke_key_id(public_key: &[u8; 32]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(KEY_ID_DOMAIN);
    digest.update(public_key);
    digest.finalize()[..16]
        .try_into()
        .expect("fixed digest slice")
}

fn verify_signature(
    public_key: [u8; 32],
    message: &[u8],
    signature: [u8; 64],
) -> Result<(), PhoneProtocolError> {
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| PhoneProtocolError::InvalidPublicKey)?
        .verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| PhoneProtocolError::InvalidSignature)
}

fn validate_window(issued_at: u64, expires_at: u64, max: u64) -> Result<(), PhoneProtocolError> {
    let lifetime = expires_at
        .checked_sub(issued_at)
        .ok_or(PhoneProtocolError::InvalidTimeWindow)?;
    if lifetime == 0 || lifetime > max {
        return Err(PhoneProtocolError::InvalidTimeWindow);
    }
    Ok(())
}

fn decode_network(value: u8) -> Result<Network, PhoneProtocolError> {
    Network::decode(value).map_err(|_| PhoneProtocolError::WrongNetwork)
}

fn decode_kind(value: u8) -> Result<AddressKind, PhoneProtocolError> {
    match value {
        0 => Ok(AddressKind::Standard),
        1 => Ok(AddressKind::Subaddress),
        _ => Err(PhoneProtocolError::InvalidAddressKind),
    }
}

fn fixed<const N: usize>(input: &[u8]) -> Result<[u8; N], PhoneProtocolError> {
    input
        .try_into()
        .map_err(|_| PhoneProtocolError::InvalidLength)
}

#[derive(Debug, Error)]
pub enum PhoneProtocolError {
    #[error("invalid E.164 phone number")]
    InvalidPhoneNumber,
    #[error("weak key material")]
    WeakKeyMaterial,
    #[error("VOPRF operation failed")]
    Voprf,
    #[error("VOPRF proof verification failed")]
    VoprfProof,
    #[error("invalid VOPRF message")]
    InvalidVoprfMessage,
    #[error("VOPRF epoch mismatch")]
    EpochMismatch,
    #[error("unexpected VOPRF server key")]
    UnexpectedServerKey,
    #[error("both VOPRF results came from the same server")]
    DuplicateServer,
    #[error("cannot create a self-pair")]
    SelfPair,
    #[error("invalid contact policy")]
    InvalidPolicy,
    #[error("invalid ask request or response")]
    InvalidAskMessage,
    #[error("invalid contact-card time window")]
    InvalidTimeWindow,
    #[error("record is expired or not yet valid")]
    Expired,
    #[error("invalid number-reassignment cooldown")]
    InvalidCooldown,
    #[error("direct sharing requires a receive address")]
    MissingReceiveAddress,
    #[error("non-direct policy must not contain a receive address")]
    UnexpectedReceiveAddress,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("invalid Monero address kind")]
    InvalidAddressKind,
    #[error("wrong Monero network")]
    WrongNetwork,
    #[error("HPKE operation failed")]
    Hpke,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("unexpected participant sequence")]
    UnexpectedSequence,
    #[error("unexpected publisher")]
    UnexpectedPublisher,
    #[error("wrong HPKE recipient")]
    WrongRecipient,
    #[error("encrypted envelope binding mismatch")]
    EnvelopeBinding,
    #[error("unexpected directory signing key")]
    UnexpectedDirectoryKey,
    #[error("directory entry has no authorized publisher")]
    UnauthorizedPublisher,
    #[error("directory entry targets an unknown or retired HPKE key")]
    UnknownRecipientKey,
    #[error("duplicate or unsorted snapshot record")]
    DuplicateOrUnsorted,
    #[error("invalid header")]
    InvalidHeader,
    #[error("invalid length")]
    InvalidLength,
    #[error("non-canonical encoding")]
    NonCanonical,
    #[error("oversized input")]
    Oversized,
    #[error("integer overflow")]
    Overflow,
    #[error("secure randomness unavailable")]
    RandomnessUnavailable,
    #[error(transparent)]
    Name(#[from] crate::name::NameProtocolError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use proptest::prelude::*;

    fn address(seed: u64) -> PublicAddress {
        PublicAddress::new(
            AddressKind::Subaddress,
            (Scalar::from(seed + 1) * ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
            (Scalar::from(seed + 2) * ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        )
        .unwrap()
    }

    fn token(value: u8) -> PhoneToken {
        PhoneToken([value; 32])
    }

    #[test]
    fn strict_e164_contract() {
        assert_eq!(normalize_e164("+50761234567").unwrap(), "+50761234567");
        assert!(normalize_e164("50761234567").is_err());
        assert!(normalize_e164("+507 61234567").is_err());
        assert!(normalize_e164("+01234567").is_err());
        assert!(normalize_e164("+1234567").is_err());
        assert!(normalize_e164("+1234567890123456").is_err());
    }

    #[test]
    fn two_independent_voprf_proofs_are_required() {
        let first = OprfServerKey::from_seed(7, &[1; 32]).unwrap();
        let second = OprfServerKey::from_seed(7, &[2; 32]).unwrap();
        let (first_session, first_request) = OprfClientSession::blind("+50761234567", 7).unwrap();
        let (second_session, second_request) = OprfClientSession::blind("+50761234567", 7).unwrap();
        assert_ne!(
            first_request.blinded_element,
            second_request.blinded_element
        );
        let first_evaluation = first.evaluate(&first_request).unwrap();
        let second_evaluation = second.evaluate(&second_request).unwrap();
        let first_output = first_session
            .finalize(&first_evaluation, first.public_key())
            .unwrap();
        let second_output = second_session
            .finalize(&second_evaluation, second.public_key())
            .unwrap();
        let combined = combine_phone_token(
            first.public_key(),
            first_output,
            second.public_key(),
            second_output,
        )
        .unwrap();
        assert_eq!(
            combined,
            combine_phone_token(
                second.public_key(),
                second_output,
                first.public_key(),
                first_output
            )
            .unwrap()
        );
        assert!(combine_phone_token(
            first.public_key(),
            first_output,
            first.public_key(),
            first_output
        )
        .is_err());
    }

    #[test]
    fn forged_or_wrong_server_evaluation_fails() {
        let first = OprfServerKey::from_seed(1, &[3; 32]).unwrap();
        let second = OprfServerKey::from_seed(1, &[4; 32]).unwrap();
        let (session, request) = OprfClientSession::blind("+491701234567", 1).unwrap();
        let evaluation = first.evaluate(&request).unwrap();
        assert!(session.finalize(&evaluation, second.public_key()).is_err());

        let (session, request) = OprfClientSession::blind("+491701234567", 1).unwrap();
        let mut evaluation = first.evaluate(&request).unwrap();
        evaluation.proof[0] ^= 1;
        assert!(session.finalize(&evaluation, first.public_key()).is_err());
    }

    #[test]
    fn voprf_wire_messages_and_client_state_round_trip() {
        let server = OprfServerKey::from_seed(10, &[10; 32]).unwrap();
        let (session, request) = OprfClientSession::blind("+50761234567", 10).unwrap();
        let state = session.export_state();
        let request = OprfBlindRequest::decode(&request.encode()).unwrap();
        let evaluation =
            OprfEvaluation::decode(&server.evaluate(&request).unwrap().encode()).unwrap();
        let restored = OprfClientSession::restore("+50761234567", 10, state).unwrap();
        restored.finalize(&evaluation, server.public_key()).unwrap();
    }

    #[test]
    fn fixed_card_and_hpke_envelope_are_bound_and_private() {
        let publisher = ContactSigningKey::from_bytes([5; 32]);
        let (recipient_private, recipient_public) = generate_hpke_keypair().unwrap();
        let card = ContactCard {
            policy: ContactPolicy::DirectReceiveAddress,
            network: Network::Mainnet,
            issued_at: 1_000,
            expires_at: 2_000,
            sequence: 4,
            publisher_token: token(10),
            recipient_token: token(11),
            address: Some(address(3)),
        };
        let envelope = ContactEnvelope::seal(&card, &publisher, recipient_public).unwrap();
        let encoded_card = card.encode_fixed().unwrap();
        assert_eq!(encoded_card.len(), CONTACT_CARD_BYTES);
        assert!(!envelope
            .ciphertext
            .windows(32)
            .any(|window| window == card.address.unwrap().public_spend_key));
        assert_eq!(
            envelope
                .open(
                    publisher.public_key(),
                    &recipient_private,
                    recipient_public,
                    1_500,
                )
                .unwrap(),
            card
        );

        let mut tampered = envelope.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(tampered
            .open(
                publisher.public_key(),
                &recipient_private,
                recipient_public,
                1_500,
            )
            .is_err());
        let (wrong_private, wrong_public) = generate_hpke_keypair().unwrap();
        assert!(envelope
            .open(publisher.public_key(), &wrong_private, wrong_public, 1_500)
            .is_err());
    }

    #[test]
    fn signed_snapshot_is_offline_searchable_and_tamper_evident() {
        let verification = ContactSigningKey::from_bytes([6; 32]);
        let directory = ContactSigningKey::from_bytes([7; 32]);
        let publisher = ContactSigningKey::from_bytes([8; 32]);
        let (_, publisher_hpke) = generate_hpke_keypair().unwrap();
        let (recipient_private, recipient_hpke) = generate_hpke_keypair().unwrap();
        let participant = ParticipantRecord::authorized(
            1,
            token(20),
            publisher.public_key(),
            publisher_hpke,
            1_000,
            2_000,
            1,
            &verification,
        )
        .unwrap();
        let recipient_signing = ContactSigningKey::from_bytes([9; 32]);
        let recipient_participant = ParticipantRecord::authorized(
            1,
            token(21),
            recipient_signing.public_key(),
            recipient_hpke,
            1_000,
            2_000,
            1,
            &verification,
        )
        .unwrap();
        let card = ContactCard {
            policy: ContactPolicy::DirectReceiveAddress,
            network: Network::Mainnet,
            issued_at: 1_000,
            expires_at: 2_000,
            sequence: 1,
            publisher_token: token(20),
            recipient_token: token(21),
            address: Some(address(20)),
        };
        let envelope = ContactEnvelope::seal(&card, &publisher, recipient_hpke).unwrap();
        let snapshot = SignedDirectorySnapshot::signed(
            3,
            1_000,
            2_000,
            vec![participant, recipient_participant],
            vec![DirectoryEntry {
                envelope: envelope.clone(),
            }],
            &directory,
        )
        .unwrap();
        snapshot
            .verify(directory.public_key(), verification.public_key(), 1_500)
            .unwrap();
        let pair = derive_pair_id(token(20), token(21)).unwrap();
        let found = snapshot.find_pair(pair).next().unwrap();
        assert_eq!(
            found
                .envelope
                .open(
                    publisher.public_key(),
                    &recipient_private,
                    recipient_hpke,
                    1_500,
                )
                .unwrap(),
            card
        );

        let encoded = snapshot.encode().unwrap();
        let decoded = SignedDirectorySnapshot::decode(&encoded).unwrap();
        decoded
            .verify(directory.public_key(), verification.public_key(), 1_500)
            .unwrap();
        let mut tampered = encoded;
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        assert!(SignedDirectorySnapshot::decode(&tampered)
            .and_then(|value| value.verify(
                directory.public_key(),
                verification.public_key(),
                1_500
            ))
            .is_err());
    }

    #[test]
    fn participant_revocation_is_canonical_signed_and_bounded() {
        let participant = ContactSigningKey::from_bytes([11; 32]);
        let wrong_participant = ContactSigningKey::from_bytes([12; 32]);
        let revocation =
            ParticipantRevocation::signed(token(30), 1_000, 2_000, 1_600, 8, &participant).unwrap();
        revocation.verify(participant.public_key(), 1_500).unwrap();
        assert!(revocation
            .verify(wrong_participant.public_key(), 1_500)
            .is_err());
        assert!(revocation.verify(participant.public_key(), 2_000).is_err());

        let encoded = revocation.encode();
        assert_eq!(ParticipantRevocation::decode(&encoded).unwrap(), revocation);
        let mut tampered = encoded;
        tampered[104] ^= 1;
        assert!(ParticipantRevocation::decode(&tampered)
            .and_then(|value| value.verify(participant.public_key(), 1_500))
            .is_err());
        assert!(ParticipantRevocation::signed(
            token(30),
            1_000,
            2_000,
            1_000 + MAX_NUMBER_REASSIGNMENT_COOLDOWN_SECONDS + 1,
            9,
            &participant,
        )
        .is_err());
    }

    #[test]
    fn permit_refresh_is_canonical_signed_short_lived_and_participant_bound() {
        let participant = ContactSigningKey::from_bytes([41; 32]);
        let wrong_participant = ContactSigningKey::from_bytes([42; 32]);
        let request =
            PermitRefreshRequest::signed(7, token(40), 12, 1_000, 1_300, [43; 16], &participant)
                .unwrap();
        request
            .verify(7, 12, participant.public_key(), 1_100)
            .unwrap();
        assert!(request
            .verify(8, 12, participant.public_key(), 1_100)
            .is_err());
        assert!(request
            .verify(7, 13, participant.public_key(), 1_100)
            .is_err());
        assert!(request
            .verify(7, 12, wrong_participant.public_key(), 1_100)
            .is_err());
        assert!(request
            .verify(7, 12, participant.public_key(), 1_300)
            .is_err());

        let encoded = request.encode();
        assert_eq!(PermitRefreshRequest::decode(&encoded).unwrap(), request);
        let mut tampered = encoded;
        tampered[80] ^= 1;
        assert!(PermitRefreshRequest::decode(&tampered)
            .and_then(|value| value.verify(7, 12, participant.public_key(), 1_100))
            .is_err());
        assert!(PermitRefreshRequest::signed(
            7,
            token(40),
            12,
            1_000,
            1_301,
            [43; 16],
            &participant,
        )
        .is_err());
    }

    #[test]
    fn contact_revocation_is_canonical_signed_and_bounded() {
        let publisher = ContactSigningKey::from_bytes([13; 32]);
        let wrong_publisher = ContactSigningKey::from_bytes([14; 32]);
        let pair_id = derive_pair_id(token(31), token(32)).unwrap();
        let revocation =
            ContactRevocation::signed(pair_id, token(31), 1_000, 2_000, 9, &publisher).unwrap();
        revocation.verify(publisher.public_key(), 1_500).unwrap();
        assert!(revocation
            .verify(wrong_publisher.public_key(), 1_500)
            .is_err());
        assert!(revocation.verify(publisher.public_key(), 2_000).is_err());

        let encoded = revocation.encode();
        assert_eq!(ContactRevocation::decode(&encoded).unwrap(), revocation);
        let mut tampered = encoded;
        tampered[128] ^= 1;
        assert!(ContactRevocation::decode(&tampered)
            .and_then(|value| value.verify(publisher.public_key(), 1_500))
            .is_err());
    }

    #[test]
    fn ask_request_and_response_are_fixed_private_and_bound() {
        let requester_signing = ContactSigningKey::from_bytes([50; 32]);
        let responder_signing = ContactSigningKey::from_bytes([51; 32]);
        let (requester_private, requester_hpke) = generate_hpke_keypair().unwrap();
        let (responder_private, responder_hpke) = generate_hpke_keypair().unwrap();
        let pair_id = derive_pair_id(token(50), token(51)).unwrap();
        let request = AskRequest {
            network: Network::Mainnet,
            pair_id,
            request_id: [52; 32],
            requester_token: token(50),
            target_token: token(51),
            issued_at: 1_000,
            expires_at: 1_600,
            sequence: 1,
        };
        let request_envelope =
            AskEnvelope::seal_request(&request, &requester_signing, responder_hpke).unwrap();
        assert_eq!(request_envelope.encode().len(), ASK_ENVELOPE_BYTES);
        assert_eq!(
            request_envelope
                .open_request(
                    requester_signing.public_key(),
                    &responder_private,
                    responder_hpke,
                    1_200,
                )
                .unwrap(),
            request
        );
        assert!(!request_envelope
            .ciphertext
            .windows(32)
            .any(|window| window == request.request_id));

        let response = AskResponse {
            decision: AskDecision::Approved,
            network: Network::Mainnet,
            pair_id,
            request_id: request.request_id,
            responder_token: request.target_token,
            requester_token: request.requester_token,
            issued_at: 1_200,
            expires_at: 1_800,
            sequence: 1,
            address: Some(address(50)),
        };
        let response_envelope =
            AskEnvelope::seal_response(&response, &responder_signing, requester_hpke).unwrap();
        assert_ne!(
            request_envelope.message_id(),
            response_envelope.message_id()
        );
        assert_eq!(
            response_envelope
                .open_response(
                    responder_signing.public_key(),
                    &requester_private,
                    requester_hpke,
                    1_300,
                )
                .unwrap(),
            response
        );

        let mut tampered = response_envelope.encode();
        tampered[230] ^= 1;
        assert!(AskEnvelope::decode(&tampered)
            .and_then(|value| value.open_response(
                responder_signing.public_key(),
                &requester_private,
                requester_hpke,
                1_300,
            ))
            .is_err());
    }

    #[test]
    fn ask_response_requires_a_fresh_subaddress_or_no_address() {
        let pair_id = derive_pair_id(token(60), token(61)).unwrap();
        let declined = AskResponse {
            decision: AskDecision::Declined,
            network: Network::Testnet,
            pair_id,
            request_id: [62; 32],
            responder_token: token(60),
            requester_token: token(61),
            issued_at: 1_000,
            expires_at: 1_100,
            sequence: 1,
            address: None,
        };
        assert_eq!(
            AskResponse::decode_fixed(&declined.encode_fixed().unwrap()).unwrap(),
            declined
        );

        let mut invalid = declined.clone();
        invalid.decision = AskDecision::Approved;
        assert!(invalid.validate().is_err());

        invalid.address = Some(PublicAddress {
            kind: AddressKind::Standard,
            ..address(60)
        });
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn ask_mailbox_poll_is_short_lived_owner_authenticated_and_cursor_bound() {
        let participant = ContactSigningKey::from_bytes([63; 32]);
        let wrong_participant = ContactSigningKey::from_bytes([64; 32]);
        let (_, hpke_public_key) = generate_hpke_keypair().unwrap();
        let hpke_key_id = hpke_key_id(&hpke_public_key);
        let poll = AskMailboxPoll::signed(
            AskMessageKind::Request,
            token(63),
            4,
            hpke_key_id,
            12,
            1_000,
            1_200,
            [65; 16],
            &participant,
        )
        .unwrap();
        poll.verify(4, participant.public_key(), hpke_key_id, 1_100)
            .unwrap();
        assert!(poll
            .verify(4, wrong_participant.public_key(), hpke_key_id, 1_100)
            .is_err());
        assert!(poll
            .verify(4, participant.public_key(), [0; 16], 1_100)
            .is_err());
        assert!(poll
            .verify(5, participant.public_key(), hpke_key_id, 1_100)
            .is_err());
        assert!(poll
            .verify(4, participant.public_key(), hpke_key_id, 1_200)
            .is_err());

        let encoded = poll.encode();
        assert_eq!(AskMailboxPoll::decode(&encoded).unwrap(), poll);
        let mut tampered = encoded;
        tampered[70] ^= 1;
        assert!(AskMailboxPoll::decode(&tampered)
            .and_then(|value| value.verify(4, participant.public_key(), hpke_key_id, 1_100))
            .is_err());
    }

    proptest! {
        #[test]
        fn phone_decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..3000)) {
            let _ = ContactCard::decode_fixed(&bytes);
            let _ = AskRequest::decode_fixed(&bytes);
            let _ = AskResponse::decode_fixed(&bytes);
            let _ = AskEnvelope::decode(&bytes);
            let _ = AskMailboxPoll::decode(&bytes);
            let _ = ParticipantRecord::decode(&bytes);
            let _ = ParticipantRevocation::decode(&bytes);
            let _ = ContactEnvelope::decode(&bytes);
            let _ = ContactRevocation::decode(&bytes);
            let _ = SignedDirectorySnapshot::decode(&bytes);
        }
    }
}
