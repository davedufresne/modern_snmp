#![doc(html_root_url = "https://docs.rs/snmp_usm/0.2.1")]

//! # Implementation of the User-based Security Model (USM) for SNMPv3
//!
//! SNMP USM provides SNMP message level security according to RFC 3414 and RFC 3826. It implements
//! primitives that can be used by a security subsystem.
//!
//! Implemented features of USM:
//!
//! * HMAC-MD5-96 Authentication Protocol
//! * HMAC-SHA-96 Authentication Protocol
//! * Timeliness verification
//! * DES encryption
//! * AES encryption
//!
//! ## Authentication and Privacy
//!
//! When privacy is used with authentication, the privacy key must use the same message-digest
//! algorithm as the authentication key. As an example, if the [AuthKey](struct.AuthKey.html) is
//! constructed with a [LocalizedKey](struct.LocalizedKey.html) specialized with the MD5
//! message-digest algorithm, then the [PrivKey](struct.PrivKey.html) must be constructed with a
//! `LocalizedKey` specialized with the MD5 message-digest algorithm.
//!
//! ## Authentication and time synchronization
//!
//! If authenticated communication is required, then the discovery process should also establish
//! time synchronization with the authoritative SNMP engine. This may be accomplished by sending an
//! authenticated Request message with the value of msgAuthoritativeEngineID set to the previously
//! learned snmpEngineID and with the values of msgAuthoritativeEngineBoots and
//! msgAuthoritativeEngineTime set to zero.
//!
//! ## Examples
//!
//! A fictional message processing subsystem is used to clarify the examples.
//!
//! ```no_run
//! use snmp_usm::{
//!     Aes128PrivKey, AuthKey, LocalizedMd5Key, PrivKey, SecurityParams, WithLocalizedKey, Sha1
//! };
//!
//! # fn main() -> snmp_usm::SecurityResult<()> {
//! # let passwd = [];
//! # let engine_id = [];
//! # let scoped_pdu = vec![];
//! # let incoming_security_params = [];
//! // The password and engine ID are supplied by the security subsystem.
//! let localized_key = LocalizedMd5Key::new(&passwd, &engine_id);
//!
//! let priv_key = Aes128PrivKey::with_localized_key(localized_key.clone());
//! # let mut security_params = SecurityParams::decode(&incoming_security_params)?;
//! // The security parameters are constructed from the local authoritative engine data.
//! let (encrypted_scoped_pdu, salt) = priv_key.encrypt(scoped_pdu, &security_params, 0);
//!
//! // The message processing service would set the encrypted scoped PDU for the outgoing message.
//! // out_msg.set_encrypted_scoped_pdu(encrypted_scoped_pdu);
//!
//! security_params
//!     .set_username(b"username")
//!     .set_priv_params(&salt)
//!     .set_auth_params_placeholder::<Sha1>();
//! let encoded_security_params = security_params.encode();
//!
//! // The message processing service would set the security parameters of the outgoing message and
//! // encode it.
//! // out_msg.set_security_params(&encoded_security_params);
//! // let out_msg = out_msg.encode();
//!
//! let auth_key = AuthKey::new(localized_key);
//!
//! // Authenticate the outgoing message.
//! # let mut out_msg = [];
//! auth_key.auth_out_msg(&mut out_msg)?;
//!
//! // Authenticate an incoming message.
//! # let mut in_msg = [];
//! # let local_engine_id = b"";
//! # let local_engine_boots = 0;
//! # let local_engine_time = 0;
//! auth_key.auth_in_msg(&mut in_msg, local_engine_id, local_engine_boots, local_engine_time)?;
//! # Ok(())
//! # }
//! ```

mod auth_key;
mod error;
mod localized_key;
mod pos_finder;
mod priv_key;
mod security_params;

pub use auth_key::{AuthKey, Digest};
pub use error::SecurityError;
pub use localized_key::{LocalizedKey, WithLocalizedKey, ExtensionVariant};
pub use md5::Md5;
pub use priv_key::{AesPrivKey, DesPrivKey, PrivKey};
pub use security_params::SecurityParams;
pub use sha1::Sha1;
pub use sha2::{Sha256, Sha512};

/// Type alias for a localized key specialized with the MD5 message-digest algorithm.
pub type LocalizedMd5Key<'a> = LocalizedKey<'a, Md5>;
/// Type alias for a localized key specialized with the SHA-1 message-digest algorithm.
pub type LocalizedSha1Key<'a> = LocalizedKey<'a, Sha1>;
/// Type alias for a localized key specialized with the SHA-256 message-digest algorithm.
pub type LocalizedSha256Key<'a> = LocalizedKey<'a, Sha256>;
/// Type alias for a localized key specialized with the SHA-512 message-digest algorithm.
pub type LocalizedSha512Key<'a> = LocalizedKey<'a, Sha512>;

/// Type alias for an authentication key specialized with the MD5 message-digest algorithm.
pub type Md5AuthKey<'a> = AuthKey<'a, Md5>;
/// Type alias for an authentication key specialized with SHA-1 message-digest algorithm.
pub type Sha1AuthKey<'a> = AuthKey<'a, Sha1>;
/// Type alias for an authentication key specialized with SHA-256 message-digest algorithm.
pub type Sha256AuthKey<'a> = AuthKey<'a, Sha256>;
/// Type alias for an authentication key specialized with SHA-512 message-digest algorithm.
pub type Sha512AuthKey<'a> = AuthKey<'a, Sha512>;

/// Type alias for the result of a security operation.
pub type SecurityResult<T> = Result<T, SecurityError>;

// Type alias for all AES privacy keys
pub type Aes128PrivKey<'a, D> = AesPrivKey<'a, D, 128>;
pub type Aes192PrivKey<'a, D> = AesPrivKey<'a, D, 192>;
pub type Aes256PrivKey<'a, D> = AesPrivKey<'a, D, 256>;
