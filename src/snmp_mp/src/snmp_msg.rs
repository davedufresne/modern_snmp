use crate::{MsgProcessingError, MsgProcessingResult, ScopedPdu, ScopedPduData, SNMP_V3};
use std::mem;
use yasna::{self, ASN1Error, ASN1ErrorKind, DERWriter};

/// SNMP message that can be encoded and sent over the network.
///
/// The default security model is the User-based Security Model (USM) for version 3 of the Simple
/// Network Management Protocol (SNMPv3).
///
/// # Examples
///
/// ```
/// use snmp_mp::SnmpMsg;
///
/// let mut msg = SnmpMsg::new(1);
/// msg.set_reportable_flag();
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SnmpMsg {
    version: u32,
    id: u32,
    max_size: u32,
    flags: SnmpMsgFlags,
    security_model: u32,
    security_params: Vec<u8>,
    pub scoped_pdu_data: ScopedPduData,
}

impl SnmpMsg {
    /// The smallest value that can be used as a message ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// assert_eq!(SnmpMsg::MSG_ID_MIN, 0);
    /// ```
    pub const MSG_ID_MIN: u32 = 0;

    /// The largest value that can be used as a message ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// assert_eq!(SnmpMsg::MSG_ID_MAX, 2_147_483_647);
    /// ```
    pub const MSG_ID_MAX: u32 = 2_147_483_647;

    /// The largest UDP packet size for IPv4.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// assert_eq!(SnmpMsg::MAX_UDP_PACKET_SIZE, 65_507);
    /// ```
    pub const MAX_UDP_PACKET_SIZE: usize = 65_507;

    /// Security model used for each `SnmpMsg`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// assert_eq!(SnmpMsg::USER_BASE_SECURITY_MODEL, 3);
    /// ```
    pub const USER_BASE_SECURITY_MODEL: u32 = 3;

    /// Constructs a new empty `SnmpMsg` with the specified ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let msg = SnmpMsg::new(1);
    /// ```
    pub fn new(id: u32) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    /// Constructs a new empty `SnmpMsg` with the specified ID and scoped PDU.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{SnmpMsg, ScopedPdu};
    /// let msg = SnmpMsg::with_scoped_pdu(1, ScopedPdu::new(1));
    pub fn with_scoped_pdu(id: u32, scoped_pdu: ScopedPdu) -> Self {
        Self {
            id,
            scoped_pdu_data: ScopedPduData::Plaintext(scoped_pdu),
            ..Default::default()
        }
    }

    /// Returns the message ID.
    ///
    /// The message ID is used to coordinate request messages and responses. It should be generated
    /// in a manner that avoids re-use of any outstanding values.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// # let msg = SnmpMsg::new(1);
    /// let msg_id = msg.id();
    /// ```
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Sets the message ID.
    ///
    /// The expected range is is between [MSG_ID_MIN](#associatedconstant.MSG_ID_MIN) and
    /// [MSG_ID_MAX](#associatedconstant.MSG_ID_MAX). The maximum value is not enforced.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// # let mut msg = SnmpMsg::new(1);
    /// msg.set_id(1234);
    /// assert_eq!(msg.id(), 1234);
    /// ```
    pub fn set_id(&mut self, id: u32) -> &mut Self {
        self.id = id;
        self
    }

    /// Returns the maximum allowed size supported by the sender of the message when encoded.
    ///
    /// The default value is [MAX_UDP_PACKET_SIZE](#associatedconstant.MAX_UDP_PACKET_SIZE).
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let msg = SnmpMsg::new(1);
    /// assert_eq!(msg.max_size(), SnmpMsg::MAX_UDP_PACKET_SIZE as u32);
    /// ```
    pub fn max_size(&self) -> u32 {
        self.max_size
    }

    /// Sets the maximum allowed size supported by the sender of the message when encoded.
    ///
    /// The default value is [MAX_UDP_PACKET_SIZE](#associatedconstant.MAX_UDP_PACKET_SIZE).
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// # let mut msg = SnmpMsg::new(1);
    /// msg.set_max_size(576);
    /// assert_eq!(msg.max_size(), 576);
    /// ```
    pub fn set_max_size(&mut self, max_size: u32) -> &Self {
        self.max_size = max_size;
        self
    }

    /// Returns `true` if the message is reportable.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let mut msg = SnmpMsg::new(1);
    /// msg.set_reportable_flag();
    /// assert!(msg.is_reportable());
    /// ```
    pub fn is_reportable(&self) -> bool {
        self.flags.contains(SnmpMsgFlags::REPORTABLE)
    }

    /// Sets the reportable flag.
    ///
    /// The reportable flag is a secondary aid in determining whether a Report PDU MUST be sent. It
    /// is only used in cases where the PDU portion of a message cannot be decoded, due to, for
    /// example, an incorrect encryption key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let mut msg = SnmpMsg::new(1);
    /// msg.set_reportable_flag();
    /// assert!(msg.is_reportable());
    /// ```
    pub fn set_reportable_flag(&mut self) -> &mut Self {
        self.flags.insert(SnmpMsgFlags::REPORTABLE);
        self
    }

    /// Returns `true` if the message is authenticated.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let mut msg = SnmpMsg::new(1);
    /// msg.set_auth_flag();
    /// assert!(msg.is_auth());
    /// ```
    pub fn is_auth(&self) -> bool {
        self.flags.contains(SnmpMsgFlags::AUTHENTICATION)
    }

    /// Sets the authentication flag.
    ///
    /// The security model must identify the security name on whose behalf the SNMP message was
    /// generated whether or no the authentication flag is set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let mut msg = SnmpMsg::new(1);
    /// msg.set_auth_flag();
    /// assert!(msg.is_auth());
    pub fn set_auth_flag(&mut self) -> &mut Self {
        self.flags.insert(SnmpMsgFlags::AUTHENTICATION);
        self
    }

    /// Returns the security model used by the sender.
    ///
    /// The default value is
    /// [USER_BASE_SECURITY_MODEL](#associatedconstant.USER_BASE_SECURITY_MODEL).
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let msg = SnmpMsg::new(1);
    /// assert_eq!(msg.security_model(), SnmpMsg::USER_BASE_SECURITY_MODEL);
    /// ```
    pub fn security_model(&self) -> u32 {
        self.security_model
    }

    /// Sets the security model used by the sender.
    ///
    /// The default value is
    /// [USER_BASE_SECURITY_MODEL](#associatedconstant.USER_BASE_SECURITY_MODEL). The expected
    /// value range is between 1 and 2_147_483_647.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let mut msg = SnmpMsg::new(1);
    /// msg.set_security_model(1);
    /// assert_eq!(msg.security_model(), 1);
    /// ```
    pub fn set_security_model(&mut self, security_model: u32) -> &Self {
        self.security_model = security_model;
        self
    }

    /// Returns the security parameters.
    ///
    /// The security parameters are exclusively used by the security model.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// # let msg = SnmpMsg::new(1);
    /// let security_params = msg.security_params();
    /// ```
    pub fn security_params(&self) -> &[u8] {
        &self.security_params
    }

    /// Sets the security parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let mut msg = SnmpMsg::new(1);
    /// let security_params = msg.set_security_params(b"security_params");
    /// assert_eq!(msg.security_params(), b"security_params");
    /// ```
    pub fn set_security_params(&mut self, params: &[u8]) {
        self.security_params.clear();
        self.security_params.extend_from_slice(params);
    }

    /// Returns `true` if the message is private.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// # let encrypted_scoped_pdu = b"encrypted_scoped_pdu".to_vec();
    /// let mut msg = SnmpMsg::new(1);
    /// msg.set_encrypted_scoped_pdu(encrypted_scoped_pdu);
    /// assert!(msg.is_private());
    /// ```
    pub fn is_private(&self) -> bool {
        self.flags.contains(SnmpMsgFlags::PRIVACY)
    }

    /// Sets the privacy flag.
    ///
    /// This flag has to be set if the encrypted scoped PDU is directly assigned
    /// (see [set_encrypted_scoped_pdu](#method.set_encrypted_scoped_pdu)).
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let mut msg = SnmpMsg::new(1);
    /// let security_params = msg.set_privacy_flag();
    /// assert!(msg.is_private());
    /// ```
    pub fn set_privacy_flag(&mut self) -> &Self {
        self.flags.insert(SnmpMsgFlags::PRIVACY);
        self
    }

    /// Sets the encrypted scoped PDU and the privacy flag.
    ///
    /// It consumes the encrypted scoped PDU.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// # let encrypted_scoped_pdu = b"encrypted_scoped_pdu".to_vec();
    /// let mut msg = SnmpMsg::new(1);
    /// msg.set_encrypted_scoped_pdu(encrypted_scoped_pdu.clone());
    /// assert!(msg.is_private());
    /// assert_eq!(msg.scoped_pdu_data.encrypted().unwrap(), &encrypted_scoped_pdu[..]);
    /// ```
    pub fn set_encrypted_scoped_pdu(&mut self, encrypted_scoped_pdu: Vec<u8>) {
        self.flags.insert(SnmpMsgFlags::PRIVACY);
        self.scoped_pdu_data = ScopedPduData::Encrypted(encrypted_scoped_pdu);
    }

    /// Encrypts the scoped PDU of the message.
    ///
    /// It takes a closure that accepts an encoded scoped PDU and returns an encrypted scoped PDU.
    /// If the message's scoped PDU is already encrypted this function does nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// # let encrypted_scoped_pdu = vec![];
    /// let mut msg = SnmpMsg::new(1);
    /// msg.encrypt_scoped_pdu(|scoped_pdu| {
    ///     // Use the security model to encrypt the scoped PDU. Ex.:
    ///     // `let encrypted_scoped_pdu = priv_key.encrypt(scoped_pdu, &security_params, salt);`
    ///     // Return the encrypted scoped PDU.
    ///     encrypted_scoped_pdu
    /// });
    /// ```
    pub fn encrypt_scoped_pdu<F>(&mut self, encrypt: F)
    where
        F: FnOnce(Vec<u8>) -> Vec<u8>,
    {
        if let Some(scoped_pdu) = self.scoped_pdu_data.plaintext() {
            let encoded_scoped_pdu = scoped_pdu.encode();
            self.scoped_pdu_data = ScopedPduData::Encrypted(encrypt(encoded_scoped_pdu));

            self.flags.insert(SnmpMsgFlags::PRIVACY);
        }
    }

    /// Decrypts the encrypted scoped PDU of the message.
    ///
    /// It takes a closure that accepts an encrypted scoped PDU and returns an encoded scoped PDU.
    /// If the message's scoped PDU is already decrypted this function does nothing and returns a
    /// reference to the scoped PDU.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// # let scoped_pdu = Some(vec![]);
    /// let mut msg = SnmpMsg::new(1);
    /// msg.decrypt_scoped_pdu(|encrypted_scoped_pdu| {
    ///     // Use the security model to decrypt the scoped PDU. Ex.:
    ///     // `let scoped_pdu = priv_key.decrypt(encrypted_scoped_pdu, &security_params);`
    ///     // Return the decrypted scoped PDU.
    ///     scoped_pdu
    /// });
    /// ```
    pub fn decrypt_scoped_pdu<F>(&mut self, decrypt: F) -> Result<&ScopedPdu, MsgProcessingError>
    where
        F: FnOnce(Vec<u8>) -> Option<Vec<u8>>,
    {
        match self.scoped_pdu_data {
            ScopedPduData::Encrypted(ref mut encrypted_scoped_pdu) => {
                let encrypted_scoped_pdu = mem::take(encrypted_scoped_pdu);

                let encoded_scoped_pdu = decrypt(encrypted_scoped_pdu);
                match encoded_scoped_pdu {
                    Some(encoded_scoped_pdu) => {
                        let scoped_pdu = ScopedPdu::decode(&encoded_scoped_pdu)?;
                        self.scoped_pdu_data = ScopedPduData::Plaintext(scoped_pdu);
                        Ok(self.scoped_pdu_data.unwrap_plaintext())
                    }
                    None => Err(MsgProcessingError::DecryptError),
                }
            }
            ScopedPduData::Plaintext(ref scoped_pdu) => Ok(scoped_pdu),
        }
    }

    /// Encodes an outgoing message.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::SnmpMsg;
    /// let msg = SnmpMsg::new(1);
    /// let encoded_msg = msg.encode();
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_u32(self.version);
                self.encode_header(writer.next());
                self.encode_security_params(writer.next());
                self.encode_scoped_pdu_data(writer.next());
            })
        })
    }

    fn encode_scoped_pdu_data(&self, writer: DERWriter) {
        match &self.scoped_pdu_data {
            ScopedPduData::Plaintext(ref scoped_pdu) => writer.write_der(&scoped_pdu.encode()),
            ScopedPduData::Encrypted(ciphertext) => writer.write_bytes(ciphertext),
        }
    }

    fn encode_header(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            writer.next().write_u32(self.id);
            writer.next().write_u32(self.max_size);
            writer.next().write_bytes(&[self.flags.bits()]);
            writer.next().write_u32(self.security_model);
        });
    }

    fn encode_security_params(&self, writer: DERWriter) {
        writer.write_bytes(&self.security_params);
    }

    /// Decodes an incoming message.
    ///
    /// # Errors
    ///
    /// When a value field in a variable binding is invalid a result with
    /// [BadValue](enum.MsgProcessingError.html#variant.BadValue) error is returned.
    ///
    /// If the version of the message is not 3 a result with
    /// [BadVersion](enum.MsgProcessingError.html#variant.BadVersion) error is returned.
    ///
    /// When the message is not properly formed a result with
    /// [MalformedMsg](enum.MsgProcessingError.html#variant.MalformedMsg) error is returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use snmp_mp::SnmpMsg;
    /// # fn main() -> snmp_mp::MsgProcessingResult<()> {
    /// # let encoded_msg = [];
    /// let msg = SnmpMsg::decode(&encoded_msg)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &[u8]) -> MsgProcessingResult<Self> {
        let mut bad_version = false;

        let result = yasna::parse_ber(buf, |reader| {
            reader.read_sequence(|reader| {
                let version = reader.next().read_u32()?;
                if version != SNMP_V3 {
                    bad_version = true;
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }

                let mut id = u32::default();
                let mut max_size = u32::default();
                let mut flags = SnmpMsgFlags::default();
                let mut security_model = u32::default();
                reader.next().read_sequence(|reader| {
                    id = reader.next().read_u32()?;
                    max_size = reader.next().read_u32()?;

                    let flags_bytes = reader.next().read_bytes()?;
                    flags = SnmpMsgFlags::from_bits_truncate(*flags_bytes.first().unwrap_or(&0));

                    security_model = reader.next().read_u32()?;

                    Ok(())
                })?;

                let security_params = reader.next().read_bytes()?;

                let scoped_pdu_data = if flags.contains(SnmpMsgFlags::PRIVACY) {
                    ScopedPduData::Encrypted(reader.next().read_bytes()?)
                } else {
                    let scoped_pdu = ScopedPdu::decode_from_reader(reader.next())?;
                    ScopedPduData::Plaintext(scoped_pdu)
                };

                Ok(SnmpMsg {
                    version,
                    id,
                    max_size,
                    flags,
                    security_model,
                    security_params,
                    scoped_pdu_data,
                })
            })
        });

        result.map_err(|_| {
            if bad_version {
                MsgProcessingError::BadVersion
            } else {
                MsgProcessingError::MalformedMsg
            }
        })
    }
}

impl Default for SnmpMsg {
    fn default() -> Self {
        SnmpMsg {
            id: 0,
            version: SNMP_V3,
            max_size: Self::MAX_UDP_PACKET_SIZE as u32,
            security_model: Self::USER_BASE_SECURITY_MODEL,
            flags: SnmpMsgFlags::default(),
            security_params: Vec::default(),
            scoped_pdu_data: ScopedPduData::default(),
        }
    }
}

bitflags! {
    #[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
    struct SnmpMsgFlags: u8 {
        const AUTHENTICATION = 0b0000_0001;
        const PRIVACY = 0b0000_0010;
        const REPORTABLE = 0b0000_0100;
    }
}
