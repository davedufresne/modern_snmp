use std::convert::TryFrom;
use yasna::{self, ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, DERWriter, Tag, TagClass};

use crate::{MsgProcessingError, MsgProcessingResult, PduErrorStatus, PduType, VarBind};

/// Scoped PDU contained in an SNMP message.
///
/// Builder methods are provided to update the scoped PDU.
///
/// # Examples
///
/// ```
/// use snmp_mp::{PduType, ScopedPdu};
///
/// let mut scoped_pdu = ScopedPdu::new(1);
/// scoped_pdu
///     .set_pdu_type(PduType::GetNextRequest)
///     .set_engine_id(b"engine_id");
/// ```
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct ScopedPdu {
    engine_id: Vec<u8>,
    context_name: Vec<u8>,
    pdu_type: PduType,
    request_id: i32,
    error_status: PduErrorStatus,
    error_index: u32,
    var_binds: Vec<VarBind>,
}

impl ScopedPdu {
    /// The smallest value that can be used as a request ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// assert_eq!(ScopedPdu::REQUEST_ID_MIN, -214_783_648);
    /// ```
    pub const REQUEST_ID_MIN: i32 = -214_783_648;

    /// The largest value that can be used as a request ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// assert_eq!(ScopedPdu::REQUEST_ID_MAX, 214_783_647);
    /// ```
    pub const REQUEST_ID_MAX: i32 = 214_783_647;

    /// Constructs a new empty `ScopedPdu`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// let scoped_pdu = ScopedPdu::new(1);
    /// ```
    pub fn new(request_id: i32) -> Self {
        Self {
            request_id,
            ..Default::default()
        }
    }

    /// Returns the context engine ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// # let scoped_pdu = ScopedPdu::new(1);
    /// let engine_id = scoped_pdu.engine_id();
    /// ```
    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    /// Sets the context engine ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// let mut scoped_pdu = ScopedPdu::new(1);
    /// scoped_pdu.set_engine_id(b"engine_id");
    /// assert_eq!(scoped_pdu.engine_id(), b"engine_id");
    /// ```
    pub fn set_engine_id(&mut self, engine_id: &[u8]) -> &mut Self {
        self.engine_id.clear();
        self.engine_id.extend_from_slice(engine_id);
        self
    }

    /// Returns the context name.
    ///
    /// The context name field in conjunction with the context engine ID field, identifies the
    /// particular context associated with the management information contained in the PDU portion
    /// of the message. The contextName is unique within the SNMP entity specified by the
    /// context engine ID, which may realize the managed objects referenced within the PDU.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// # let scoped_pdu = ScopedPdu::new(1);
    /// let context_name = scoped_pdu.context_name();
    /// ```
    pub fn context_name(&self) -> &[u8] {
        &self.context_name
    }

    /// Sets the context name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// let mut scoped_pdu = ScopedPdu::new(1);
    /// scoped_pdu.set_context_name(b"context_name");
    /// assert_eq!(scoped_pdu.context_name(), b"context_name");
    /// ```
    pub fn set_context_name(&mut self, context_name: &[u8]) -> &mut Self {
        self.context_name.clear();
        self.context_name.extend_from_slice(context_name);
        self
    }

    /// Returns the PDU type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// # let scoped_pdu = ScopedPdu::new(1);
    /// let pdu_type = scoped_pdu.pdu_type();
    /// ```
    pub fn pdu_type(&self) -> PduType {
        self.pdu_type
    }

    /// Sets the PDU type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{PduType, ScopedPdu};
    /// let mut scoped_pdu = ScopedPdu::new(1);
    /// scoped_pdu.set_pdu_type(PduType::GetNextRequest);
    /// assert_eq!(scoped_pdu.pdu_type(), PduType::GetNextRequest);
    /// ```
    pub fn set_pdu_type(&mut self, pdu_type: PduType) -> &mut Self {
        self.pdu_type = pdu_type;
        self
    }

    /// Returns the request ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// # let scoped_pdu = ScopedPdu::new(1);
    /// let request_id = scoped_pdu.request_id();
    /// ```
    pub fn request_id(&self) -> i32 {
        self.request_id
    }

    /// Sets the request ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// let mut scoped_pdu = ScopedPdu::new(1);
    /// scoped_pdu.set_request_id(1234);
    /// assert_eq!(scoped_pdu.request_id(), 1234);
    /// ```
    pub fn set_request_id(&mut self, request_id: i32) -> &mut Self {
        self.request_id = request_id;
        self
    }

    /// Returns the error status.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// # let scoped_pdu = ScopedPdu::new(1);
    /// let error_status = scoped_pdu.error_status();
    /// ```
    pub fn error_status(&self) -> PduErrorStatus {
        self.error_status
    }

    /// Sets the error status.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{PduErrorStatus, PduType, ScopedPdu};
    /// let mut scoped_pdu = ScopedPdu::new(1);
    /// scoped_pdu.set_error_status(PduErrorStatus::NoSuchName);
    /// assert_eq!(scoped_pdu.error_status(), PduErrorStatus::NoSuchName);
    /// ```
    pub fn set_error_status(&mut self, error_status: PduErrorStatus) -> &mut Self {
        self.error_status = error_status;
        self
    }

    /// Returns the error index.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// # let scoped_pdu = ScopedPdu::new(1);
    /// assert_eq!(scoped_pdu.error_index(), 0);
    /// ```
    pub fn error_index(&self) -> u32 {
        self.error_index
    }

    /// Sets the error index.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// let mut scoped_pdu = ScopedPdu::new(1);
    /// scoped_pdu.set_error_index(1);
    /// assert_eq!(scoped_pdu.error_index(), 1);
    /// ```
    pub fn set_error_index(&mut self, error_index: u32) -> &mut Self {
        self.error_index = error_index;
        self
    }

    /// Returns the variable bindings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// # let scoped_pdu = ScopedPdu::new(1);
    /// let var_binds = scoped_pdu.var_binds();
    /// ```
    pub fn var_binds(&self) -> &[VarBind] {
        &self.var_binds
    }

    /// Sets the variable bindings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ObjectIdent, ScopedPdu, VarBind, VarValue};
    /// # let oid = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    /// # let var_bind = VarBind::new(oid);
    /// # let var_binds = vec![var_bind];
    ///
    /// let mut scoped_pdu = ScopedPdu::new(1);
    /// scoped_pdu.set_var_binds(var_binds.clone());
    /// assert_eq!(var_binds, scoped_pdu.var_binds());
    /// ```
    pub fn set_var_binds<I>(&mut self, var_binds_iter: I) -> &mut Self
    where
        I: IntoIterator<Item = VarBind>,
    {
        self.var_binds.clear();
        self.var_binds.extend(var_binds_iter);
        self
    }

    /// Appends an element to the back of the list of variable bindings.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ObjectIdent, ScopedPdu, VarBind};
    /// let oid = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    /// let var_bind = VarBind::new(oid);
    ///
    /// let mut scoped_pdu = ScopedPdu::new(1);
    /// scoped_pdu.push_var_bind(var_bind.clone());
    /// assert_eq!(vec![var_bind], scoped_pdu.var_binds());
    /// ```
    pub fn push_var_bind(&mut self, var_bind: VarBind) -> &mut Self {
        self.var_binds.push(var_bind);
        self
    }

    /// Encodes a scoped PDU.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::ScopedPdu;
    /// let scoped_pdu = ScopedPdu::new(1);
    /// let encoded_scoped_pdu = scoped_pdu.encode();
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_bytes(&self.engine_id);
                writer.next().write_bytes(&self.context_name);
                self.encode_pdu(writer.next());
            })
        })
    }

    /// Decodes an encoded scope PDU.
    ///
    /// # Errors
    ///
    /// If the scoped PDU is not properly formed a result with
    /// [MalformedMsg](enum.MsgProcessingError.html#variant.MalformedMsg) error is returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use snmp_mp::ScopedPdu;
    /// # fn main() -> snmp_mp::MsgProcessingResult<()> {
    /// # let encoded_scoped_pdu = [];
    /// let scoped_pdu = ScopedPdu::decode(&encoded_scoped_pdu)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &[u8]) -> MsgProcessingResult<Self> {
        // The BER parsing library returns an error when there are bytes remaining at the end of
        // the buffer. This might happen when parsing a decrypted scoped PDU since the padding is
        // not removed. So return the scoped PDU even if the 'Extra' error is raised.
        let mut scoped_pdu = None;

        let result = yasna::parse_ber(buf, |reader| {
            scoped_pdu = Some(Self::decode_from_reader(reader)?);
            Ok(())
        });

        if let Err(error) = result {
            if error.kind() != ASN1ErrorKind::Extra {
                return Err(MsgProcessingError::MalformedMsg);
            }
        }

        Ok(scoped_pdu.unwrap())
    }

    // Decodes an encoded scope PDU using the supplied BER reader. Used internally to decode
    // plaintext and decrypted scoped PDU.
    pub(crate) fn decode_from_reader(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let engine_id = reader.next().read_bytes()?;
            let context_name = reader.next().read_bytes()?;

            // Each PDU type has it's own implicit tag.
            let tag = reader.next().lookahead_tag()?;
            if tag.tag_class != TagClass::ContextSpecific {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }

            let pdu_type = PduType::try_from(tag.tag_number)
                .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;

            reader.next().read_tagged_implicit(tag, |reader| {
                reader.read_sequence(|reader| {
                    let request_id = reader.next().read_i32()?;

                    let error_status = PduErrorStatus::try_from(reader.next().read_u8()?)
                        .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;

                    let error_index = reader.next().read_u32()?;
                    let var_binds = reader.next().collect_sequence_of(VarBind::decode)?;

                    Ok(Self {
                        engine_id,
                        context_name,
                        pdu_type,
                        request_id,
                        error_status,
                        error_index,
                        var_binds,
                    })
                })
            })
        })
    }

    fn encode_pdu(&self, writer: DERWriter) {
        let pdu_type = self.pdu_type as u64;
        let tag = Tag::context(pdu_type);

        writer.write_tagged_implicit(tag, |writer| {
            writer.write_sequence(|writer| {
                writer.next().write_i32(self.request_id);
                writer.next().write_u8(self.error_status as u8);
                writer.next().write_u32(self.error_index);

                writer.next().write_sequence_of(|writer| {
                    for var_bind in &self.var_binds {
                        var_bind.encode(writer.next());
                    }
                });
            });
        })
    }
}
