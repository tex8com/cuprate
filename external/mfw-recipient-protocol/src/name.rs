use core::fmt;

use curve25519_dalek::{edwards::CompressedEdwardsY, traits::Identity};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MFW_ARBITRARY_DATA_MARKER: u8 = 0x7f;
pub const MFW_MAX_NONCE_BYTES: usize = 255;
pub const MAX_NAME_BYTES: usize = 63;
pub const MAX_NAME_RECORD_BYTES: usize = 251;
pub const COMMIT_RECORD_BYTES: usize = 38;
pub const MFW_MAGIC: &[u8; 4] = b"MFWN";
pub const MFW_VERSION: u8 = 1;

const SIGNATURE_DOMAIN: &[u8] = b"TEX8/MFW/name-record/v1";
const COMMIT_DOMAIN: &[u8] = b"TEX8/MFW/name-commit/v1";
const FINGERPRINT_DOMAIN: &[u8] = b"TEX8/MFW/name-fingerprint/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Network {
    Mainnet = 0,
    Testnet = 1,
    Stagenet = 2,
}

impl Network {
    pub fn decode(value: u8) -> Result<Self, NameProtocolError> {
        match value {
            0 => Ok(Self::Mainnet),
            1 => Ok(Self::Testnet),
            2 => Ok(Self::Stagenet),
            _ => Err(NameProtocolError::UnknownNetwork),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddressKind {
    Standard = 0,
    Subaddress = 1,
}

impl AddressKind {
    fn decode(value: u8) -> Result<Self, NameProtocolError> {
        match value {
            0 => Ok(Self::Standard),
            1 => Ok(Self::Subaddress),
            _ => Err(NameProtocolError::UnknownAddressKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PublicAddress {
    pub kind: AddressKind,
    pub public_spend_key: [u8; 32],
    pub public_view_key: [u8; 32],
}

impl PublicAddress {
    pub fn new(
        kind: AddressKind,
        public_spend_key: [u8; 32],
        public_view_key: [u8; 32],
    ) -> Result<Self, NameProtocolError> {
        validate_monero_public_key(&public_spend_key)?;
        validate_monero_public_key(&public_view_key)?;
        Ok(Self {
            kind,
            public_spend_key,
            public_view_key,
        })
    }

    pub fn validate(&self) -> Result<(), NameProtocolError> {
        validate_monero_public_key(&self.public_spend_key)?;
        validate_monero_public_key(&self.public_view_key)
    }
}

fn validate_monero_public_key(bytes: &[u8; 32]) -> Result<(), NameProtocolError> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(NameProtocolError::InvalidMoneroPublicKey)?;
    if point == curve25519_dalek::edwards::EdwardsPoint::identity() || !point.is_torsion_free() {
        return Err(NameProtocolError::InvalidMoneroPublicKey);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CanonicalName(String);

impl CanonicalName {
    pub fn parse(input: &str) -> Result<Self, NameProtocolError> {
        let normalized = input.to_ascii_lowercase();
        let label = normalized
            .strip_suffix(".mfw")
            .unwrap_or(&normalized)
            .to_owned();
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_NAME_BYTES {
            return Err(NameProtocolError::InvalidNameLength);
        }
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return Err(NameProtocolError::InvalidName);
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(NameProtocolError::InvalidName);
        }
        Ok(Self(label))
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NameProtocolError> {
        let value = core::str::from_utf8(bytes).map_err(|_| NameProtocolError::InvalidName)?;
        let parsed = Self::parse(value)?;
        if parsed.0.as_bytes() != bytes || value.ends_with(".mfw") {
            return Err(NameProtocolError::NonCanonical);
        }
        Ok(parsed)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn display_name(&self) -> String {
        format!("{}.mfw", self.0)
    }
}

impl fmt::Display for CanonicalName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.display_name())
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct NameSigningKey([u8; 32]);

impl NameSigningKey {
    pub fn generate() -> Result<Self, NameProtocolError> {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| NameProtocolError::RandomnessUnavailable)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum NameOperation {
    Claim = 2,
    Update = 3,
    Renew = 4,
    Revoke = 5,
}

impl NameOperation {
    fn decode(value: u8) -> Result<Self, NameProtocolError> {
        match value {
            2 => Ok(Self::Claim),
            3 => Ok(Self::Update),
            4 => Ok(Self::Renew),
            5 => Ok(Self::Revoke),
            _ => Err(NameProtocolError::UnknownOperation),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRecord {
    pub commitment: [u8; 32],
}

impl CommitRecord {
    pub fn for_claim(
        network: Network,
        name: &CanonicalName,
        owner_public_key: &[u8; 32],
        salt: &[u8; 16],
    ) -> Self {
        let mut hash = Sha256::new();
        hash.update(COMMIT_DOMAIN);
        hash.update([network as u8]);
        hash.update([u8::try_from(name.as_str().len()).expect("name length is bounded")]);
        hash.update(name.as_str().as_bytes());
        hash.update(owner_public_key);
        hash.update(salt);
        Self {
            commitment: hash.finalize().into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(COMMIT_RECORD_BYTES);
        encoded.extend_from_slice(MFW_MAGIC);
        encoded.push(MFW_VERSION);
        encoded.push(1);
        encoded.extend_from_slice(&self.commitment);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, NameProtocolError> {
        if encoded.len() != COMMIT_RECORD_BYTES {
            return Err(NameProtocolError::InvalidLength);
        }
        if &encoded[..4] != MFW_MAGIC || encoded[4] != MFW_VERSION || encoded[5] != 1 {
            return Err(NameProtocolError::InvalidHeader);
        }
        let commitment = encoded[6..38]
            .try_into()
            .map_err(|_| NameProtocolError::InvalidLength)?;
        Ok(Self { commitment })
    }

    pub fn to_tx_extra_nonce_field(&self) -> Result<Vec<u8>, NameProtocolError> {
        wrap_arbitrary_nonce(&self.encode())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameRecord {
    pub operation: NameOperation,
    pub sequence: u32,
    pub name: CanonicalName,
    pub owner_public_key: [u8; 32],
    pub address: PublicAddress,
    /// Claim salt for `CLAIM`; predecessor fingerprint for later operations.
    pub binding: [u8; 16],
    pub signature: [u8; 64],
}

impl NameRecord {
    pub fn signed_claim(
        network: Network,
        name: CanonicalName,
        address: PublicAddress,
        salt: [u8; 16],
        owner_key: &NameSigningKey,
    ) -> Result<Self, NameProtocolError> {
        let mut record = Self {
            operation: NameOperation::Claim,
            sequence: 0,
            name,
            owner_public_key: owner_key.public_key(),
            address,
            binding: salt,
            signature: [0_u8; 64],
        };
        record.validate_fields()?;
        record.signature = owner_key.sign(&record.signing_message(network)?);
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn signed_transition(
        network: Network,
        operation: NameOperation,
        sequence: u32,
        name: CanonicalName,
        new_owner_public_key: [u8; 32],
        address: PublicAddress,
        predecessor: &NameRecord,
        current_owner_key: &NameSigningKey,
    ) -> Result<Self, NameProtocolError> {
        if operation == NameOperation::Claim {
            return Err(NameProtocolError::WrongOperation);
        }
        if predecessor.name != name
            || predecessor.owner_public_key != current_owner_key.public_key()
            || sequence
                != predecessor
                    .sequence
                    .checked_add(1)
                    .ok_or(NameProtocolError::Overflow)?
        {
            return Err(NameProtocolError::InvalidTransition);
        }
        VerifyingKey::from_bytes(&new_owner_public_key)
            .map_err(|_| NameProtocolError::InvalidOwnerPublicKey)?;
        let mut record = Self {
            operation,
            sequence,
            name,
            owner_public_key: new_owner_public_key,
            address,
            binding: predecessor.fingerprint()?,
            signature: [0_u8; 64],
        };
        record.validate_fields()?;
        record.signature = current_owner_key.sign(&record.signing_message(network)?);
        Ok(record)
    }

    pub fn verify_claim(&self, network: Network) -> Result<(), NameProtocolError> {
        if self.operation != NameOperation::Claim || self.sequence != 0 {
            return Err(NameProtocolError::WrongOperation);
        }
        self.verify_signature(network, &self.owner_public_key)
    }

    /// Verify the record bytes against the explicitly supplied historical
    /// signer. Index clients use this for a transition response; full
    /// predecessor/inclusion verification remains a separate chain-proof
    /// responsibility.
    pub fn verify_with_signer(
        &self,
        network: Network,
        signing_owner_public_key: [u8; 32],
    ) -> Result<(), NameProtocolError> {
        self.verify_signature(network, &signing_owner_public_key)
    }

    pub fn verify_transition(
        &self,
        network: Network,
        predecessor: &NameRecord,
    ) -> Result<(), NameProtocolError> {
        if self.operation == NameOperation::Claim
            || self.name != predecessor.name
            || self.sequence
                != predecessor
                    .sequence
                    .checked_add(1)
                    .ok_or(NameProtocolError::Overflow)?
            || self.binding != predecessor.fingerprint()?
        {
            return Err(NameProtocolError::InvalidTransition);
        }
        self.verify_signature(network, &predecessor.owner_public_key)
    }

    fn verify_signature(
        &self,
        network: Network,
        signing_public_key: &[u8; 32],
    ) -> Result<(), NameProtocolError> {
        self.validate_fields()?;
        let key = VerifyingKey::from_bytes(signing_public_key)
            .map_err(|_| NameProtocolError::InvalidOwnerPublicKey)?;
        key.verify_strict(
            &self.signing_message(network)?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| NameProtocolError::InvalidSignature)
    }

    fn signing_message(&self, network: Network) -> Result<Vec<u8>, NameProtocolError> {
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 1 + 187);
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.push(network as u8);
        message.extend_from_slice(&self.unsigned_bytes()?);
        Ok(message)
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, NameProtocolError> {
        self.validate_fields()?;
        let mut encoded = Vec::with_capacity(MAX_NAME_RECORD_BYTES - 64);
        encoded.extend_from_slice(MFW_MAGIC);
        encoded.push(MFW_VERSION);
        encoded.push(self.operation as u8);
        encoded.extend_from_slice(&self.sequence.to_be_bytes());
        encoded.push(
            u8::try_from(self.name.as_str().len())
                .map_err(|_| NameProtocolError::InvalidNameLength)?,
        );
        encoded.extend_from_slice(self.name.as_str().as_bytes());
        encoded.extend_from_slice(&self.owner_public_key);
        encoded.push(self.address.kind as u8);
        encoded.extend_from_slice(&self.address.public_spend_key);
        encoded.extend_from_slice(&self.address.public_view_key);
        encoded.extend_from_slice(&self.binding);
        Ok(encoded)
    }

    pub fn encode(&self) -> Result<Vec<u8>, NameProtocolError> {
        let mut encoded = self.unsigned_bytes()?;
        encoded.extend_from_slice(&self.signature);
        if encoded.len() > MAX_NAME_RECORD_BYTES {
            return Err(NameProtocolError::Oversized);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, NameProtocolError> {
        if encoded.len() < 4 + 1 + 1 + 4 + 1 + 1 + 32 + 1 + 32 + 32 + 16 + 64
            || encoded.len() > MAX_NAME_RECORD_BYTES
        {
            return Err(NameProtocolError::InvalidLength);
        }
        let mut cursor = Cursor::new(encoded);
        cursor.expect(MFW_MAGIC)?;
        if cursor.u8()? != MFW_VERSION {
            return Err(NameProtocolError::UnsupportedVersion);
        }
        let operation = NameOperation::decode(cursor.u8()?)?;
        let sequence = cursor.u32()?;
        let name_len = usize::from(cursor.u8()?);
        if name_len == 0 || name_len > MAX_NAME_BYTES {
            return Err(NameProtocolError::InvalidNameLength);
        }
        let name = CanonicalName::from_canonical_bytes(cursor.take(name_len)?)?;
        let owner_public_key = cursor.array()?;
        VerifyingKey::from_bytes(&owner_public_key)
            .map_err(|_| NameProtocolError::InvalidOwnerPublicKey)?;
        let kind = AddressKind::decode(cursor.u8()?)?;
        let public_spend_key = cursor.array()?;
        let public_view_key = cursor.array()?;
        let address = PublicAddress::new(kind, public_spend_key, public_view_key)?;
        let binding = cursor.array()?;
        let signature = cursor.array()?;
        cursor.finish()?;
        let record = Self {
            operation,
            sequence,
            name,
            owner_public_key,
            address,
            binding,
            signature,
        };
        record.validate_fields()?;
        if record.encode()?.as_slice() != encoded {
            return Err(NameProtocolError::NonCanonical);
        }
        Ok(record)
    }

    pub fn fingerprint(&self) -> Result<[u8; 16], NameProtocolError> {
        let mut hash = Sha256::new();
        hash.update(FINGERPRINT_DOMAIN);
        hash.update(self.encode()?);
        let digest = hash.finalize();
        Ok(digest[..16].try_into().expect("fixed digest slice"))
    }

    pub fn claim_commitment(&self, network: Network) -> Result<CommitRecord, NameProtocolError> {
        if self.operation != NameOperation::Claim {
            return Err(NameProtocolError::WrongOperation);
        }
        Ok(CommitRecord::for_claim(
            network,
            &self.name,
            &self.owner_public_key,
            &self.binding,
        ))
    }

    pub fn to_tx_extra_nonce_field(&self) -> Result<Vec<u8>, NameProtocolError> {
        wrap_arbitrary_nonce(&self.encode()?)
    }

    fn validate_fields(&self) -> Result<(), NameProtocolError> {
        CanonicalName::from_canonical_bytes(self.name.as_str().as_bytes())?;
        VerifyingKey::from_bytes(&self.owner_public_key)
            .map_err(|_| NameProtocolError::InvalidOwnerPublicKey)?;
        self.address.validate()?;
        if self.operation == NameOperation::Claim && self.sequence != 0 {
            return Err(NameProtocolError::InvalidTransition);
        }
        if self.operation != NameOperation::Claim && self.sequence == 0 {
            return Err(NameProtocolError::InvalidTransition);
        }
        Ok(())
    }
}

fn wrap_arbitrary_nonce(payload: &[u8]) -> Result<Vec<u8>, NameProtocolError> {
    let nonce_len = payload
        .len()
        .checked_add(1)
        .ok_or(NameProtocolError::Overflow)?;
    if nonce_len > MFW_MAX_NONCE_BYTES {
        return Err(NameProtocolError::Oversized);
    }
    let mut field = Vec::with_capacity(1 + 10 + nonce_len);
    field.push(2);
    // Monero's generic tx_extra parser deserializes tx_extra_nonce as a
    // length-prefixed string, hence the length is a canonical unsigned
    // varint. The legacy add_extra_nonce_to_tx_extra convenience helper
    // writes one byte and is only parseable while the nonce is below 128
    // bytes; MFW CLAIM/RENEW records intentionally exercise the larger range.
    write_varint(
        u64::try_from(nonce_len).map_err(|_| NameProtocolError::Oversized)?,
        &mut field,
    );
    field.push(MFW_ARBITRARY_DATA_MARKER);
    field.extend_from_slice(payload);
    Ok(field)
}

pub fn extract_mfw_payloads(extra: &[u8]) -> Result<Vec<Vec<u8>>, NameProtocolError> {
    const MAX_EXTRA_BYTES: usize = 1060;
    if extra.len() > MAX_EXTRA_BYTES {
        return Err(NameProtocolError::OversizedExtra);
    }
    let mut cursor = 0_usize;
    let mut payloads = Vec::new();
    while cursor < extra.len() {
        let tag = extra[cursor];
        cursor += 1;
        match tag {
            0 => {
                while cursor < extra.len() && extra[cursor] == 0 {
                    cursor += 1;
                }
            }
            1 => {
                take_extra(extra, &mut cursor, 32)?;
            }
            2 => {
                let len = usize::try_from(read_varint(extra, &mut cursor)?)
                    .map_err(|_| NameProtocolError::Oversized)?;
                if len > MFW_MAX_NONCE_BYTES {
                    return Err(NameProtocolError::Oversized);
                }
                let nonce = take_extra(extra, &mut cursor, len)?;
                if nonce.first() == Some(&MFW_ARBITRARY_DATA_MARKER)
                    && nonce.get(1..5) == Some(MFW_MAGIC.as_slice())
                {
                    payloads.push(nonce[1..].to_vec());
                }
            }
            3 => {
                let _height = read_varint(extra, &mut cursor)?;
                take_extra(extra, &mut cursor, 32)?;
            }
            4 => {
                let count = usize::try_from(read_varint(extra, &mut cursor)?)
                    .map_err(|_| NameProtocolError::Oversized)?;
                let len = count.checked_mul(32).ok_or(NameProtocolError::Overflow)?;
                take_extra(extra, &mut cursor, len)?;
            }
            0xde => {
                let len = usize::try_from(read_varint(extra, &mut cursor)?)
                    .map_err(|_| NameProtocolError::Oversized)?;
                take_extra(extra, &mut cursor, len)?;
            }
            _ => return Err(NameProtocolError::UnknownExtraTag),
        }
    }
    Ok(payloads)
}

fn write_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn read_varint(input: &[u8], cursor: &mut usize) -> Result<u64, NameProtocolError> {
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        let byte = *input.get(*cursor).ok_or(NameProtocolError::Truncated)?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(NameProtocolError::InvalidVarint);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let mut canonical = Vec::new();
            write_varint(value, &mut canonical);
            let start = cursor
                .checked_sub(canonical.len())
                .ok_or(NameProtocolError::InvalidVarint)?;
            if input.get(start..*cursor) != Some(canonical.as_slice()) {
                return Err(NameProtocolError::NonCanonical);
            }
            return Ok(value);
        }
    }
    Err(NameProtocolError::InvalidVarint)
}

fn take_extra<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], NameProtocolError> {
    let end = cursor.checked_add(len).ok_or(NameProtocolError::Overflow)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(NameProtocolError::Truncated)?;
    *cursor = end;
    Ok(bytes)
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], NameProtocolError> {
        take_extra(self.input, &mut self.offset, len)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), NameProtocolError> {
        if self.take(expected.len())? != expected {
            return Err(NameProtocolError::InvalidHeader);
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, NameProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, NameProtocolError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| NameProtocolError::Truncated)?,
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NameProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| NameProtocolError::Truncated)
    }

    fn finish(&self) -> Result<(), NameProtocolError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(NameProtocolError::TrailingBytes)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum NameProtocolError {
    #[error("invalid name length")]
    InvalidNameLength,
    #[error("invalid name")]
    InvalidName,
    #[error("non-canonical encoding")]
    NonCanonical,
    #[error("unknown network")]
    UnknownNetwork,
    #[error("unknown address kind")]
    UnknownAddressKind,
    #[error("invalid Monero public key")]
    InvalidMoneroPublicKey,
    #[error("invalid owner public key")]
    InvalidOwnerPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid transition")]
    InvalidTransition,
    #[error("wrong operation")]
    WrongOperation,
    #[error("unknown operation")]
    UnknownOperation,
    #[error("invalid record header")]
    InvalidHeader,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("invalid record length")]
    InvalidLength,
    #[error("truncated input")]
    Truncated,
    #[error("trailing bytes")]
    TrailingBytes,
    #[error("oversized value")]
    Oversized,
    #[error("oversized transaction extra")]
    OversizedExtra,
    #[error("unknown transaction-extra tag")]
    UnknownExtraTag,
    #[error("invalid varint")]
    InvalidVarint,
    #[error("integer overflow")]
    Overflow,
    #[error("secure randomness unavailable")]
    RandomnessUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use proptest::prelude::*;

    fn address(seed: u64, kind: AddressKind) -> PublicAddress {
        let spend = (Scalar::from(seed + 1) * ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let view = (Scalar::from(seed + 2) * ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        PublicAddress::new(kind, spend, view).unwrap()
    }

    #[test]
    fn canonical_name_contract() {
        assert_eq!(CanonicalName::parse("Alice.MFW").unwrap().as_str(), "alice");
        assert!(CanonicalName::parse("").is_err());
        assert!(CanonicalName::parse("-alice").is_err());
        assert!(CanonicalName::parse("alice-").is_err());
        assert!(CanonicalName::parse("älice").is_err());
        assert!(CanonicalName::parse(&"a".repeat(64)).is_err());
        assert!(CanonicalName::parse(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn largest_record_fits_nonce() {
        let owner = NameSigningKey::from_bytes([7; 32]);
        let record = NameRecord::signed_claim(
            Network::Mainnet,
            CanonicalName::parse(&"a".repeat(63)).unwrap(),
            address(3, AddressKind::Subaddress),
            [9; 16],
            &owner,
        )
        .unwrap();
        assert_eq!(record.encode().unwrap().len(), MAX_NAME_RECORD_BYTES);
        let extra = record.to_tx_extra_nonce_field().unwrap();
        assert_eq!(extra.len(), 1 + 2 + 1 + MAX_NAME_RECORD_BYTES);
        assert_eq!(extra[0], 2);
        assert_eq!(&extra[1..3], &[0xfc, 0x01]);
        assert_eq!(extra[3], MFW_ARBITRARY_DATA_MARKER);
        let extracted = extract_mfw_payloads(&extra).unwrap();
        assert_eq!(extracted, vec![record.encode().unwrap()]);
    }

    #[test]
    fn rejects_legacy_single_byte_nonce_length_above_127() {
        let owner = NameSigningKey::from_bytes([17; 32]);
        let record = NameRecord::signed_claim(
            Network::Mainnet,
            CanonicalName::parse(&"b".repeat(63)).unwrap(),
            address(13, AddressKind::Subaddress),
            [19; 16],
            &owner,
        )
        .unwrap();
        let payload = record.encode().unwrap();
        let nonce_len = 1 + payload.len();
        assert!(nonce_len > 127);

        let mut incompatible = vec![2, u8::try_from(nonce_len).unwrap()];
        incompatible.push(MFW_ARBITRARY_DATA_MARKER);
        incompatible.extend_from_slice(&payload);

        assert!(extract_mfw_payloads(&incompatible).is_err());
    }

    #[test]
    fn claim_and_transition_signatures_are_bound() {
        let owner = NameSigningKey::from_bytes([1; 32]);
        let next_owner = NameSigningKey::from_bytes([2; 32]);
        let claim = NameRecord::signed_claim(
            Network::Mainnet,
            CanonicalName::parse("alice").unwrap(),
            address(10, AddressKind::Subaddress),
            [3; 16],
            &owner,
        )
        .unwrap();
        claim.verify_claim(Network::Mainnet).unwrap();
        assert!(claim.verify_claim(Network::Testnet).is_err());

        let update = NameRecord::signed_transition(
            Network::Mainnet,
            NameOperation::Update,
            1,
            claim.name.clone(),
            next_owner.public_key(),
            address(20, AddressKind::Subaddress),
            &claim,
            &owner,
        )
        .unwrap();
        update.verify_transition(Network::Mainnet, &claim).unwrap();

        let mut tampered = update.clone();
        tampered.address = address(21, AddressKind::Subaddress);
        assert!(tampered
            .verify_transition(Network::Mainnet, &claim)
            .is_err());
    }

    #[test]
    fn decode_rejects_trailing_and_noncanonical() {
        let owner = NameSigningKey::from_bytes([4; 32]);
        let claim = NameRecord::signed_claim(
            Network::Stagenet,
            CanonicalName::parse("test-name").unwrap(),
            address(30, AddressKind::Standard),
            [5; 16],
            &owner,
        )
        .unwrap();
        let encoded = claim.encode().unwrap();
        assert_eq!(NameRecord::decode(&encoded).unwrap(), claim);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(NameRecord::decode(&trailing).is_err());
    }

    #[test]
    fn extracts_mfw_after_standard_public_key() {
        let commit = CommitRecord {
            commitment: [8; 32],
        };
        let mut extra = vec![1];
        extra.extend_from_slice(
            &(Scalar::from(42_u64) * ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        );
        extra.extend_from_slice(&commit.to_tx_extra_nonce_field().unwrap());
        assert_eq!(extract_mfw_payloads(&extra).unwrap(), vec![commit.encode()]);
    }

    proptest! {
        #[test]
        fn name_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = NameRecord::decode(&bytes);
            let _ = CommitRecord::decode(&bytes);
            let _ = extract_mfw_payloads(&bytes);
        }
    }
}
