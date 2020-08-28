use std::error::Error;
use std::fmt::{Display, Formatter, Result};
use std::io;

/// The error type for message processing related operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum MsgProcessingError {
    /// The contents of the value field in a variable binding does not, according to the ASN.1
    /// language, manifest a type, length, and value that is consistent with that required for the
    /// variable.
    BadValue,
    /// Bad SNMP version.
    BadVersion,
    /// Decryption error occurred.
    DecryptError,
    /// The outgoing SNMP message is too big.
    TooBig,
    /// The SNMP message was malformed.
    MalformedMsg,
}

impl Display for MsgProcessingError {
    fn fmt(&self, formatter: &mut Formatter) -> Result {
        match self {
            Self::BadValue => "bad variable binding value".fmt(formatter),
            Self::BadVersion => "bad SNMP version".fmt(formatter),
            Self::DecryptError => "decryption error".fmt(formatter),
            Self::TooBig => "outgoing message too big".fmt(formatter),
            Self::MalformedMsg => "malformed incoming message".fmt(formatter),
        }
    }
}

impl Error for MsgProcessingError {}

#[doc(hidden)]
impl From<MsgProcessingError> for io::Error {
    fn from(parse_error: MsgProcessingError) -> Self {
        Self::new(io::ErrorKind::InvalidData, parse_error)
    }
}
