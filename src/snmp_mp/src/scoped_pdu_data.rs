use crate::ScopedPdu;

/// Represents either the plaintext scoped PDU if the privacy flag is not set, or it represents an
/// encrypted PDU encoded as a byte string.
///
/// # Examples
///
/// ```
/// use snmp_mp::{ScopedPdu, ScopedPduData};
///
/// let scoped_pdu_data = ScopedPduData::Plaintext(ScopedPdu::new(1));
/// let scoped_pdu = scoped_pdu_data.plaintext();
/// assert_eq!(scoped_pdu.unwrap(), &ScopedPdu::new(1));
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ScopedPduData {
    /// Plaintext scoped PDU.
    Plaintext(ScopedPdu),
    /// Encrypted PDU as a byte string.
    Encrypted(Vec<u8>),
}

impl ScopedPduData {
    /// Returns a reference to the plaintext scoped PDU, or `None` if the scoped PDU is encrypted.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ScopedPdu, ScopedPduData};
    /// let scoped_pdu_data = ScopedPduData::Plaintext(ScopedPdu::new(1));
    /// let scoped_pdu = scoped_pdu_data.plaintext();
    /// assert_eq!(scoped_pdu.unwrap(), &ScopedPdu::new(1));
    /// ```
    pub fn plaintext(&self) -> Option<&ScopedPdu> {
        match self {
            ScopedPduData::Plaintext(ref scoped_pdu) => Some(scoped_pdu),
            _ => None,
        }
    }

    /// Returns a mutable reference to the plaintext scoped PDU, or `None` if the scoped PDU is
    /// encrypted.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ScopedPdu, ScopedPduData};
    /// let mut scoped_pdu_data = ScopedPduData::Plaintext(ScopedPdu::new(1));
    /// let scoped_pdu = scoped_pdu_data.plaintext_mut().unwrap();
    /// scoped_pdu.set_request_id(1234);
    /// assert_eq!(scoped_pdu.request_id(), 1234);
    /// ```
    pub fn plaintext_mut(&mut self) -> Option<&mut ScopedPdu> {
        match self {
            ScopedPduData::Plaintext(ref mut scoped_pdu) => Some(scoped_pdu),
            _ => None,
        }
    }

    /// Returns a reference to the encrypted scoped PDU, or `None` if the scoped PDU is plaintext.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPduData;
    /// # let encrypted_scoped_pdu = b"encrypted".to_vec();
    /// let scoped_pdu_data = ScopedPduData::Encrypted(encrypted_scoped_pdu.clone());
    /// let optional_encrypted_scoped_pdu = scoped_pdu_data.encrypted();
    /// assert_eq!(optional_encrypted_scoped_pdu.unwrap(), &encrypted_scoped_pdu[..]);
    /// ```
    pub fn encrypted(&self) -> Option<&[u8]> {
        match self {
            ScopedPduData::Encrypted(ref encrypted_scoped_pdu) => Some(encrypted_scoped_pdu),
            _ => None,
        }
    }

    // Returns a reference to the plaintext scoped PDU, or panics if the scoped PDU is encrypted.
    pub(crate) fn unwrap_plaintext(&self) -> &ScopedPdu {
        match self {
            ScopedPduData::Plaintext(ref scoped_pdu) => scoped_pdu,
            _ => panic!("not a plaintext scoped PDU"),
        }
    }
}

impl Default for ScopedPduData {
    fn default() -> Self {
        Self::Plaintext(ScopedPdu::default())
    }
}
