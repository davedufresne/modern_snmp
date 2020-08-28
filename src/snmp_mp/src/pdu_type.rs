use std::convert::TryFrom;
use std::error::Error;
use std::fmt;

// `u64` is used because the BER encoding library uses this type for tag numbers.
const GET_REQUEST_TAG_NUM: u64 = 0;
const GET_NEXT_REQUEST_TAG_NUM: u64 = 1;
const RESPONSE_TAG_NUM: u64 = 2;
const SET_REQUEST_TAG_NUM: u64 = 3;
const GET_BULK_REQUEST_TAG_NUM: u64 = 5;
const INFORM_REQUEST_TAG_NUM: u64 = 6;
const SNMP_TRAP_TAG_NUM: u64 = 7;
const REPORT_TAG_NUM: u64 = 8;

/// Represents a PDU type.
///
/// PDU types are encoded as implicit tags.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum PduType {
    GetRequest = GET_REQUEST_TAG_NUM as isize,
    GetNextRequest = GET_NEXT_REQUEST_TAG_NUM as isize,
    Response = RESPONSE_TAG_NUM as isize,
    SetRequest = SET_REQUEST_TAG_NUM as isize,
    GetBulkRequest = GET_BULK_REQUEST_TAG_NUM as isize,
    InformRequest = INFORM_REQUEST_TAG_NUM as isize,
    SnmpTrap = SNMP_TRAP_TAG_NUM as isize,
    Report = REPORT_TAG_NUM as isize,
}

impl Default for PduType {
    fn default() -> Self {
        PduType::GetRequest
    }
}

/// Error returned when the conversion from `u64` to `PduType` fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IntToPduTypeError;

impl IntToPduTypeError {
    fn description(&self) -> &str {
        "not a valid PDU type"
    }
}

impl Error for IntToPduTypeError {}

impl fmt::Display for IntToPduTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(formatter)
    }
}

impl TryFrom<u64> for PduType {
    type Error = IntToPduTypeError;

    /// Tries to create a `PduType` from a `u64`.
    ///
    /// # Errors
    ///
    /// This returns an error if the `u64` doesn't match a PDU type.
    fn try_from(integer: u64) -> Result<Self, Self::Error> {
        let result = match integer {
            GET_REQUEST_TAG_NUM => Self::GetRequest,
            GET_NEXT_REQUEST_TAG_NUM => Self::GetNextRequest,
            RESPONSE_TAG_NUM => Self::Response,
            SET_REQUEST_TAG_NUM => Self::SetRequest,
            GET_BULK_REQUEST_TAG_NUM => Self::GetBulkRequest,
            INFORM_REQUEST_TAG_NUM => Self::InformRequest,
            SNMP_TRAP_TAG_NUM => Self::SnmpTrap,
            REPORT_TAG_NUM => Self::Report,
            _ => return Err(IntToPduTypeError),
        };

        Ok(result)
    }
}
