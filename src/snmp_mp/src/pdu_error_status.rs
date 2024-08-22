use std::convert::TryFrom;
use std::error::Error;
use std::fmt;

const NO_ERROR: isize = 0;
const TOO_BIG: isize = 1;
const NO_SUCH_NAME: isize = 2;
const BAD_VALUE: isize = 3;
const READ_ONLY: isize = 4;
const GEN_ERR: isize = 5;
const NO_ACCESS: isize = 6;
const WRONG_TYPE: isize = 7;
const WRONG_LENGTH: isize = 8;
const WRONG_ENCODING: isize = 9;
const WRONG_VALUE: isize = 10;
const NO_CREATION: isize = 11;
const INCONSISTENT_VALUE: isize = 12;
const RESOURCE_UNAVAILABLE: isize = 13;
const COMMIT_FAILED: isize = 14;
const UNDO_FAILED: isize = 15;
const AUTHORIZATION_ERROR: isize = 16;
const NOT_WRITABLE: isize = 17;
const INCONSISTENT_NAME: isize = 18;

/// Response PDU error status.
///
/// A non-zero value of the error-status field in a Response-PDU is used to indicate that an error
/// occurred to prevent the processing of the request.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum PduErrorStatus {
    #[default]
    NoError = NO_ERROR,
    TooBig = TOO_BIG,
    NoSuchName = NO_SUCH_NAME,
    BadValue = BAD_VALUE,
    ReadOnly = READ_ONLY,
    GenErr = GEN_ERR,
    NoAccess = NO_ACCESS,
    WrongType = WRONG_TYPE,
    WrongLength = WRONG_LENGTH,
    WrongEncoding = WRONG_ENCODING,
    WrongValue = WRONG_VALUE,
    NoCreation = NO_CREATION,
    InconsistentValue = INCONSISTENT_VALUE,
    ResourceUnavailable = RESOURCE_UNAVAILABLE,
    CommitFailed = COMMIT_FAILED,
    UndoFailed = UNDO_FAILED,
    AuthorizationError = AUTHORIZATION_ERROR,
    NotWritable = NOT_WRITABLE,
    InconsistentName = INCONSISTENT_NAME,
}

/// Error returned when the conversion from `u8` to `PduErrorStatus` fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IntToPduErrorStatusError;

impl IntToPduErrorStatusError {
    fn description(&self) -> &str {
        "not a valid PDU error status"
    }
}

impl Error for IntToPduErrorStatusError {}

impl fmt::Display for IntToPduErrorStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(formatter)
    }
}

impl TryFrom<u8> for PduErrorStatus {
    type Error = IntToPduErrorStatusError;

    /// Tries to create a `PduErrorStatus` from a `u8`.
    ///
    /// # Errors
    ///
    /// This returns an error if the `u8` doesn't match a PDU type.
    fn try_from(integer: u8) -> Result<Self, Self::Error> {
        let result = match integer as isize {
            NO_ERROR => PduErrorStatus::NoError,
            TOO_BIG => PduErrorStatus::TooBig,
            NO_SUCH_NAME => PduErrorStatus::NoSuchName,
            BAD_VALUE => PduErrorStatus::BadValue,
            READ_ONLY => PduErrorStatus::ReadOnly,
            GEN_ERR => PduErrorStatus::GenErr,
            NO_ACCESS => PduErrorStatus::NoAccess,
            WRONG_TYPE => PduErrorStatus::WrongType,
            WRONG_LENGTH => PduErrorStatus::WrongLength,
            WRONG_ENCODING => PduErrorStatus::WrongEncoding,
            WRONG_VALUE => PduErrorStatus::WrongValue,
            NO_CREATION => PduErrorStatus::NoCreation,
            INCONSISTENT_VALUE => PduErrorStatus::InconsistentValue,
            RESOURCE_UNAVAILABLE => PduErrorStatus::ResourceUnavailable,
            COMMIT_FAILED => PduErrorStatus::CommitFailed,
            UNDO_FAILED => PduErrorStatus::UndoFailed,
            AUTHORIZATION_ERROR => PduErrorStatus::AuthorizationError,
            NOT_WRITABLE => PduErrorStatus::NotWritable,
            INCONSISTENT_NAME => PduErrorStatus::InconsistentName,
            _ => return Err(IntToPduErrorStatusError),
        };

        Ok(result)
    }
}
