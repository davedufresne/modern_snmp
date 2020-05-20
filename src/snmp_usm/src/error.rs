use std::error::Error;
use std::fmt::{Display, Formatter, Result};
use std::io;

/// The error type for security related operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SecurityError {
    /// Decryption error occurred.
    DecryptError,
    /// The SNMP message was malformed.
    MalformedMsg,
    /// The security parameters were malformed.
    MalformedSecurityParams,
    /// The authentication parameters didn't match the digest.
    WrongAuthParams,
    /// The SNMP message was considered to be outside the time window.
    NotInTimeWindow,
}

impl Display for SecurityError {
    fn fmt(&self, formatter: &mut Formatter) -> Result {
        match self {
            Self::DecryptError => "decryption error".fmt(formatter),
            Self::MalformedMsg => "malformed SNMP message".fmt(formatter),
            Self::MalformedSecurityParams => "malformed security parameters".fmt(formatter),
            Self::NotInTimeWindow => "not in time window".fmt(formatter),
            Self::WrongAuthParams => "wrong authentication parameters".fmt(formatter),
        }
    }
}

impl Error for SecurityError {}

#[doc(hidden)]
impl From<SecurityError> for io::Error {
    fn from(parse_error: SecurityError) -> Self {
        Self::new(io::ErrorKind::InvalidData, parse_error)
    }
}
