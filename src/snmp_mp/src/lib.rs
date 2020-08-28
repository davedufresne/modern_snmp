#![doc(html_root_url = "https://docs.rs/snmp_mp/0.1.0")]

//! # Primitives to send and receive SNMP messages.
//!
//! Supported PDU types:
//!
//! * GetRequest
//! * GetNextRequest
//! * GetBulkRequest
//! * Response
//! * SetRequest
//! * SNMPv2-Trap
//! * InformRequest
//!
//! ## Examples
//!
//! ```
//! use snmp_mp::{ObjectIdent, SnmpMsg, VarBind};
//!
//! let mut msg = SnmpMsg::new(1);
//! msg.set_reportable_flag();
//!
//! if let Some(scoped_pdu) = msg.scoped_pdu_data.plaintext_mut() {
//!     let sys_desc = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
//!     let var_bind = VarBind::new(sys_desc);
//!
//!     scoped_pdu
//!         .set_request_id(1)
//!         .set_engine_id(b"context_engine_id")
//!         .push_var_bind(var_bind);
//! }
//!
//! let encoded_msg = msg.encode();
//! // Send the encoded message over the network.
//! ```
//!
//! [encrypt_scoped_pdu](struct.SnmpMsg.html#method.encrypt_scoped_pdu) and
//! [decrypt_scoped_pdu](struct.SnmpMsg.html#method.decrypt_scoped_pdu) are provided to make it
//! easy to use a security model:
//!
//! ```
//! # use snmp_mp::SnmpMsg;
//! # let mut msg = SnmpMsg::new(1);
//! msg.encrypt_scoped_pdu(|encoded_scoped_pdu| {
//!     // A security model encrypts and returns the scoped PDU.
//!     // let (encrypted_scoped_pdu, priv_params) =
//!     //     priv_key.encrypt(encoded_scoped_pdu, &security_params, salt);
//!     // security_params.set_priv_params(&priv_params);
//!
//!     # let encrypted_scoped_pdu = encoded_scoped_pdu;
//!     encrypted_scoped_pdu
//! });
//!
//! msg.decrypt_scoped_pdu(|encrypted_scoped_pdu| {
//!     // A security model returns the decrypted scoped PDU wrapped in an `Option`.
//!     // priv_key
//!     //     .decrypt(encrypted_scoped_pdu, &security_params)
//!     //     .ok()
//!     # None
//! });
//! ```
#[macro_use]
extern crate bitflags;

mod error;
mod object_ident;
mod pdu_error_status;
mod pdu_type;
mod scoped_pdu;
mod scoped_pdu_data;
mod snmp_msg;
mod var_bind;

pub use error::MsgProcessingError;
pub use object_ident::ObjectIdent;
pub use pdu_error_status::PduErrorStatus;
pub use pdu_type::PduType;
pub use scoped_pdu::ScopedPdu;
pub use scoped_pdu_data::ScopedPduData;
pub use snmp_msg::SnmpMsg;
pub use var_bind::{VarBind, VarValue};

/// Type alias for the result of a message processing operation.
pub type MsgProcessingResult<T> = Result<T, MsgProcessingError>;

const SNMP_V3: u32 = 3;
