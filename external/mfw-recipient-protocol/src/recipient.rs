use thiserror::Error;

use crate::name::{Network, PublicAddress};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientSource {
    AddressOrQr,
    LocalAddressBook,
    MfwName,
    PrivatePhone,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRecipient {
    pub label: String,
    pub source: RecipientSource,
    pub network: Network,
    pub address: PublicAddress,
    pub confirmations: Option<u64>,
    pub expires_at: Option<u64>,
    pub address_changed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRecipient {
    pub label: String,
    pub source: RecipientSource,
    pub network: Network,
    pub canonical_address: String,
    pub address: PublicAddress,
    pub address_changed: bool,
}

impl ResolvedRecipient {
    /// All routes converge here and then pass through the native Monero Core
    /// address encoder/parser supplied by `native_validator`.
    pub fn validate_with<F>(
        self,
        expected_network: Network,
        now: u64,
        native_validator: F,
    ) -> Result<ValidatedRecipient, RecipientValidationError>
    where
        F: FnOnce(Network, PublicAddress) -> Result<String, RecipientValidationError>,
    {
        if self.network != expected_network {
            return Err(RecipientValidationError::WrongNetwork);
        }
        self.address
            .validate()
            .map_err(|_| RecipientValidationError::InvalidPublicKey)?;
        if self.source == RecipientSource::MfwName && self.confirmations.unwrap_or(0) < 15 {
            return Err(RecipientValidationError::InsufficientConfirmations);
        }
        if self.expires_at.is_some_and(|expiry| now >= expiry) {
            return Err(RecipientValidationError::Expired);
        }
        let canonical_address = native_validator(self.network, self.address)?;
        if canonical_address.is_empty() {
            return Err(RecipientValidationError::NativeValidationFailed);
        }
        Ok(ValidatedRecipient {
            label: self.label,
            source: self.source,
            network: self.network,
            canonical_address,
            address: self.address,
            address_changed: self.address_changed,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RecipientValidationError {
    #[error("recipient is for the wrong Monero network")]
    WrongNetwork,
    #[error("recipient contains an invalid public key")]
    InvalidPublicKey,
    #[error("name has fewer than 15 confirmations")]
    InsufficientConfirmations,
    #[error("recipient record is expired")]
    Expired,
    #[error("native Monero Core rejected the recipient")]
    NativeValidationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::AddressKind;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};

    fn address() -> PublicAddress {
        PublicAddress::new(
            AddressKind::Subaddress,
            (Scalar::from(5_u64) * ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
            (Scalar::from(6_u64) * ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn every_route_requires_native_validation() {
        let resolved = ResolvedRecipient {
            label: "Alice".to_owned(),
            source: RecipientSource::MfwName,
            network: Network::Mainnet,
            address: address(),
            confirmations: Some(15),
            expires_at: Some(200),
            address_changed: false,
        };
        let validated = resolved
            .clone()
            .validate_with(Network::Mainnet, 100, |_, _| Ok("4...".to_owned()))
            .unwrap();
        assert_eq!(validated.canonical_address, "4...");
        assert_eq!(
            resolved
                .validate_with(Network::Testnet, 100, |_, _| unreachable!())
                .unwrap_err(),
            RecipientValidationError::WrongNetwork
        );
    }

    #[test]
    fn provisional_and_expired_records_fail_closed() {
        let base = ResolvedRecipient {
            label: "Alice".to_owned(),
            source: RecipientSource::MfwName,
            network: Network::Mainnet,
            address: address(),
            confirmations: Some(14),
            expires_at: Some(200),
            address_changed: false,
        };
        assert_eq!(
            base.clone()
                .validate_with(Network::Mainnet, 100, |_, _| Ok("x".into()))
                .unwrap_err(),
            RecipientValidationError::InsufficientConfirmations
        );
        let expired = ResolvedRecipient {
            confirmations: Some(15),
            ..base
        };
        assert_eq!(
            expired
                .validate_with(Network::Mainnet, 200, |_, _| Ok("x".into()))
                .unwrap_err(),
            RecipientValidationError::Expired
        );
    }
}
