//! Protocol core for public MFW names and private phone-contact resolution.
//!
//! This crate has no network or UI authority. It owns canonical encodings,
//! signatures, state transitions, RFC 9497 VOPRF messages, fixed-size contact
//! cards, and the common resolved-recipient contract.

pub mod name;
pub mod name_index;
pub mod phone;
pub mod recipient;

pub use name::{
    extract_mfw_payloads, AddressKind, CanonicalName, CommitRecord, NameOperation, NameRecord,
    NameSigningKey, Network, PublicAddress, MFW_ARBITRARY_DATA_MARKER, MFW_MAX_NONCE_BYTES,
};
pub use name_index::{
    registry_descriptor_hash, BlockInput, IndexedTransaction, NameIndex, NameIndexError,
    ProtocolParameters, Resolution, ResolutionStatus,
};
pub use phone::{
    combine_phone_token, derive_hpke_key_id, derive_pair_id, generate_hpke_keypair, normalize_e164,
    AskDecision, AskEnvelope, AskMailboxPoll, AskMessageKind, AskRequest, AskResponse, ContactCard,
    ContactEnvelope, ContactPolicy, ContactRevocation, ContactSigningKey, DirectoryEntry,
    HpkePrivateKey, OprfBlindRequest, OprfClientSession, OprfEvaluation, OprfServerKey, PairId,
    ParticipantRecord, ParticipantRevocation, PermitRefreshRequest, PhoneProtocolError, PhoneToken,
    SignedDirectorySnapshot, ASK_ENVELOPE_BYTES, ASK_MAILBOX_POLL_BYTES,
    PERMIT_REFRESH_REQUEST_BYTES, VOPRF_CLIENT_STATE_BYTES, VOPRF_EVALUATION_BYTES,
    VOPRF_REQUEST_BYTES,
};
pub use recipient::{
    RecipientSource, RecipientValidationError, ResolvedRecipient, ValidatedRecipient,
};
