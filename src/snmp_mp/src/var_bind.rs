use crate::ObjectIdent;
use std::convert::TryInto;
use yasna::{
    self, tags, ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, DERWriter, Tag, TagClass,
};

/// Represents a variable binding.
///
/// # Examples
///
/// ```
/// use snmp_mp::{ObjectIdent, VarBind, VarValue};
///
/// let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
/// let var_bind = VarBind::new(name);
/// assert_eq!(var_bind.value(), &VarValue::Unspecified);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct VarBind {
    name: ObjectIdent,
    value: VarValue,
}

impl VarBind {
    /// Constructs a new `VarBind` with the passed [ObjectIdent](struct.ObjectIdent.html) and a
    /// value of [VarValue::Unspecified](enum.VarValue.html#variant.Unspecified).
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ObjectIdent, VarBind, VarValue};
    /// let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    /// let var_bind = VarBind::new(name);
    /// assert_eq!(var_bind.value(), &VarValue::Unspecified);
    /// ```
    pub fn new(name: ObjectIdent) -> Self {
        Self {
            name,
            value: VarValue::Unspecified,
        }
    }

    /// Constructs a new `VarBind` with the passed [ObjectIdent](struct.ObjectIdent.html) and
    /// [VarValue](enum.VarValue.html).
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ObjectIdent, VarBind, VarValue};
    /// let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    /// let value = VarValue::String(b"System description".to_vec());
    /// let var_bind = VarBind::with_value(name, value);
    /// assert_eq!(var_bind.value(), &VarValue::String(b"System description".to_vec()));
    /// ```
    pub fn with_value(name: ObjectIdent, value: VarValue) -> Self {
        Self { name, value }
    }

    /// Returns the variable name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ObjectIdent, VarBind, VarValue};
    /// let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    /// let var_bind = VarBind::new(name.clone());
    /// assert_eq!(var_bind.name(), &name);
    /// ```
    pub fn name(&self) -> &ObjectIdent {
        &self.name
    }

    /// Sets the variable name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ObjectIdent, VarBind, VarValue};
    /// let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    /// let mut var_bind = VarBind::new(name);
    /// let new_name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x01]);
    /// var_bind.set_name(new_name.clone());
    ///
    /// assert_eq!(var_bind.name(), &new_name);
    /// ```
    pub fn set_name(&mut self, name: ObjectIdent) -> &mut Self {
        self.name = name;
        self
    }

    /// Returns the variable value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ObjectIdent, VarBind, VarValue};
    /// let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    /// let var_bind = VarBind::new(name);
    /// assert_eq!(var_bind.value(), &VarValue::Unspecified);
    /// ```
    pub fn value(&self) -> &VarValue {
        &self.value
    }

    /// Sets the variable value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_mp::{ObjectIdent, VarBind, VarValue};
    /// let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    /// let mut var_bind = VarBind::new(name);
    /// let new_value = VarValue::NoSuchInstance;
    /// var_bind.set_value(new_value.clone());
    ///
    /// assert_eq!(var_bind.value(), &new_value);
    /// ```
    pub fn set_value(&mut self, value: VarValue) -> &mut Self {
        self.value = value;
        self
    }

    pub(crate) fn encode(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&self.name.0);
            self.value.encode(writer.next());
        });
    }

    pub(crate) fn decode(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let name = Self::read_oid(reader.next())?;
            let value = VarValue::decode(reader.next())?;

            Ok(VarBind { name, value })
        })
    }

    // The BER parsing library returns an error when a byte equals 128. So use a more lenient OID
    // decoding scheme accepting this case.
    fn read_oid(reader: BERReader) -> ASN1Result<ObjectIdent> {
        let der_value = reader.read_tagged_der()?;
        if der_value.tag() != tags::TAG_OID {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }

        let buf = der_value.value();
        if buf.is_empty() || buf[buf.len() - 1] >= 128 {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }

        let mut components = Vec::new();
        let mut sub_id: u64 = 0;
        for &byte in buf.iter() {
            sub_id = sub_id
                .checked_mul(128)
                .ok_or_else(|| ASN1Error::new(ASN1ErrorKind::IntegerOverflow))?
                + (byte & 127) as u64;
            if (byte & 128) == 0 {
                if components.is_empty() {
                    let id_0 = if sub_id < 40 {
                        0
                    } else if sub_id < 80 {
                        1
                    } else {
                        2
                    };
                    let id_1 = sub_id - 40 * id_0;
                    components.push(id_0);
                    components.push(id_1);
                } else {
                    components.push(sub_id);
                }

                sub_id = 0;
            }
        }

        Ok(ObjectIdent::new(components))
    }
}

/// Represents a variable binding value.
///
/// # Examples
///
/// ```
/// use snmp_mp::VarValue;
///
/// let var_value = VarValue::Int(1);
/// ```
#[derive(Default, Clone, Debug, Eq, PartialEq, Hash)]
pub enum VarValue {
    /// The Integer32 type represents integer-valued information between -2^31 and 2^31-1 inclusive
    /// (-2_147_483_648 to 2_147_483_647 decimal).
    Int(i32),
    /// The OCTET STRING type represents arbitrary binary or textual data.
    String(Vec<u8>),
    /// The OBJECT IDENTIFIER type represents administratively assigned names.
    ObjectId(ObjectIdent),
    /// The IpAddress type represents a 32-bit internet address.  It is represented as an OCTET
    /// STRING of length 4, in network byte-order.
    IpAddress([u8; 4]),
    /// The Counter32 type represents a non-negative integer which monotonically increases until it
    /// reaches a maximum value of 2^32-1 (4_294_967_295 decimal), when it wraps around and starts
    /// increasing again from zero.
    Counter(u32),
    /// The Unsigned32 type represents integer-valued information between 0 and 2^32-1 inclusive (0
    /// to 4_294_967_295 decimal).
    UnsignedInt(u32),
    /// The TimeTicks type represents a non-negative integer which represents the time, modulo 2^32
    /// (4_294_967_296 decimal), in hundredths of a second between two epochs.
    TimeTicks(u32),
    /// The Opaque type is provided solely for backward-compatibility.
    Opaque(Vec<u8>),
    /// The Counter64 type represents a non-negative integer which monotonically increases until it
    /// reaches a maximum value of 2^64-1 (18_446_744_073_709_551_615 decimal), when it wraps
    /// around and starts increasing again from zero.
    BigCounter(u64),
    /// Some PDUs (e.g., the GetRequest-PDU) are concerned only with the name of a variable and not
    /// its value. In this case, the value portion of the variable binding is ignored by the
    /// receiving SNMP entity. The `UnSpecified` value is defined for use as the value portion of
    /// such bindings.
    #[default]
    Unspecified,
    /// If a variable binding's name does not have an object identifier prefix which exactly matches
    /// any variable, then its value is set to `NoSuchObject`.
    NoSuchObject,
    /// If a variable binding's name does not matches an existing instance, then its value is set to
    /// `NoSuchInstance`.
    NoSuchInstance,
    /// `EndOfMibView` signifies the end of the data in the requested view.
    EndOfMibView,
}

macro_rules! write_tagged_implicit {
    ($tag_num:expr, $writer:expr, $write_fn:expr, $val:expr) => {
        let tag = Tag::application($tag_num);
        $writer.write_tagged_implicit(tag, |writer| {
            $write_fn(writer, $val);
        })
    };
}

impl VarValue {
    const NO_SUCH_OBJECT_TAG_NUM: u64 = 0;
    const NO_SUCH_INSTANCE_TAG_NUM: u64 = 1;
    const END_OF_MIB_VIEW_TAG_NUM: u64 = 2;
    const IP_ADDRESS_TAG_NUM: u64 = 0;
    const COUNTER_TAG_NUM: u64 = 1;
    const UNSIGNED_INT_TAG_NUM: u64 = 2;
    const TIME_TICKS_INT_TAG_NUM: u64 = 3;
    const OPAQUE_TAG_NUM: u64 = 4;
    const BIG_COUNTER_TAG_NUM: u64 = 6;

    fn encode(&self, writer: DERWriter) {
        match self {
            Self::Int(i) => writer.write_i32(*i),
            Self::String(s) => writer.write_bytes(s),
            Self::ObjectId(oid) => writer.write_oid(&oid.0),
            Self::IpAddress(ip) => {
                write_tagged_implicit!(
                    Self::IP_ADDRESS_TAG_NUM,
                    writer,
                    DERWriter::write_bytes,
                    ip
                );
            }
            Self::Counter(c) => {
                write_tagged_implicit!(Self::COUNTER_TAG_NUM, writer, DERWriter::write_u32, *c);
            }
            Self::UnsignedInt(ui) => {
                write_tagged_implicit!(
                    Self::UNSIGNED_INT_TAG_NUM,
                    writer,
                    DERWriter::write_u32,
                    *ui
                );
            }
            Self::TimeTicks(tt) => {
                write_tagged_implicit!(
                    Self::TIME_TICKS_INT_TAG_NUM,
                    writer,
                    DERWriter::write_u32,
                    *tt
                );
            }
            Self::Opaque(o) => {
                write_tagged_implicit!(Self::OPAQUE_TAG_NUM, writer, DERWriter::write_bytes, o);
            }
            Self::BigCounter(bc) => {
                write_tagged_implicit!(
                    Self::BIG_COUNTER_TAG_NUM,
                    writer,
                    DERWriter::write_u64,
                    *bc
                );
            }
            Self::Unspecified => writer.write_null(),
            Self::NoSuchObject => Self::write_tagged_null(Self::NO_SUCH_OBJECT_TAG_NUM, writer),
            Self::NoSuchInstance => Self::write_tagged_null(Self::NO_SUCH_INSTANCE_TAG_NUM, writer),
            Self::EndOfMibView => Self::write_tagged_null(Self::END_OF_MIB_VIEW_TAG_NUM, writer),
        }
    }

    fn write_tagged_null(tag_num: u64, writer: DERWriter) {
        writer.write_tagged_implicit(Tag::context(tag_num), |writer| {
            writer.write_null();
        });
    }

    fn decode(reader: BERReader) -> ASN1Result<Self> {
        let tag = reader.lookahead_tag()?;
        let value = match tag {
            tags::TAG_NULL => {
                reader.read_null()?;
                VarValue::Unspecified
            }
            Tag {
                tag_class: TagClass::ContextSpecific,
                tag_number,
            } => {
                reader
                    .read_tagged_implicit(Tag::context(tag_number), |reader| reader.read_null())?;

                match tag_number {
                    Self::NO_SUCH_OBJECT_TAG_NUM => VarValue::NoSuchObject,
                    Self::NO_SUCH_INSTANCE_TAG_NUM => VarValue::NoSuchInstance,
                    Self::END_OF_MIB_VIEW_TAG_NUM => VarValue::EndOfMibView,
                    _ => return Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
                }
            }
            tags::TAG_INTEGER => Self::Int(reader.read_i32()?),
            tags::TAG_OCTETSTRING => Self::String(reader.read_bytes()?),
            tags::TAG_OID => Self::ObjectId(ObjectIdent(reader.read_oid()?)),
            Tag {
                tag_class: TagClass::Application,
                tag_number: _,
            } => Self::decode_app_value(reader, tag)?,
            _ => return Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        };

        Ok(value)
    }

    fn decode_app_value(reader: BERReader, tag: Tag) -> ASN1Result<Self> {
        let value = match tag.tag_number {
            Self::IP_ADDRESS_TAG_NUM => {
                let ip = reader.read_tagged_implicit(tag, |reader| reader.read_bytes())?;
                let arr = ip[..]
                    .try_into()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                Self::IpAddress(arr)
            }
            Self::COUNTER_TAG_NUM => {
                let counter = reader.read_tagged_implicit(tag, |reader| reader.read_u32())?;
                Self::Counter(counter)
            }
            Self::UNSIGNED_INT_TAG_NUM => {
                let u_int = reader.read_tagged_implicit(tag, |reader| reader.read_u32())?;
                Self::UnsignedInt(u_int)
            }
            Self::TIME_TICKS_INT_TAG_NUM => {
                let time_ticks = reader.read_tagged_implicit(tag, |reader| reader.read_u32())?;
                Self::TimeTicks(time_ticks)
            }
            Self::OPAQUE_TAG_NUM => {
                let opaque = reader.read_tagged_implicit(tag, |reader| reader.read_bytes())?;
                Self::Opaque(opaque)
            }
            Self::BIG_COUNTER_TAG_NUM => {
                let counter = reader.read_tagged_implicit(tag, |reader| reader.read_u64())?;
                Self::BigCounter(counter)
            }
            _ => return Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        };

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_defaults_to_unspecified() {
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
        let var_bind = VarBind::new(name);

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_int() {
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00]);
        let var_bind = VarBind::with_value(name, VarValue::Int(76));

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x0D, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00, 0x02, 0x01,
            0x4C,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_string() {
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]);
        let var_bind = VarBind::with_value(name, VarValue::String(b"davids-mbp.lan".to_vec()));

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x1A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x04, 0x0E,
            0x64, 0x61, 0x76, 0x69, 0x64, 0x73, 0x2D, 0x6D, 0x62, 0x70, 0x2E, 0x6C, 0x61, 0x6E,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_oid() {
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x03, 0x01, 0x02, 0x01,
        ]);
        let oid =
            ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x01, 0x02]);
        let var_bind = VarBind::with_value(name, VarValue::ObjectId(oid));

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x18, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x03, 0x01, 0x02,
            0x01, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x01, 0x02,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_ip() {
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x04, 0x14, 0x01, 0x01, 0x7F, 0x00, 0x00, 0x01,
        ]);
        let ip = [127, 0, 0, 1];
        let var_bind = VarBind::with_value(name, VarValue::IpAddress(ip));

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x15, 0x06, 0x0D, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x04, 0x14, 0x01, 0x01, 0x7F,
            0x00, 0x00, 0x01, 0x40, 0x04, 0x7F, 0x00, 0x00, 0x01,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_counter() {
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01,
        ]);
        let var_bind = VarBind::with_value(name, VarValue::Counter(685125474));

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01,
            0x41, 0x04, 0x28, 0xD6, 0x2F, 0x62,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_unsigned_int() {
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01,
        ]);
        let var_bind = VarBind::with_value(name, VarValue::UnsignedInt(685125474));

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01,
            0x42, 0x04, 0x28, 0xD6, 0x2F, 0x62,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_time_ticks() {
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00]);
        let var_bind = VarBind::with_value(name, VarValue::TimeTicks(696006));

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x0F, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x03,
            0x0A, 0x9E, 0xC6,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_time_opaque() {
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0x7E5, 0x0A, 0x01, 0x06, 0x01,
        ]);
        let var_bind = VarBind::with_value(
            name,
            VarValue::Opaque(vec![0x9F, 0x78, 0x04, 0x3F, 0xE3, 0xD0, 0x00]),
        );

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x16, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x8F, 0x65, 0x0A, 0x01, 0x06,
            0x01, 0x44, 0x07, 0x9F, 0x78, 0x04, 0x3F, 0xE3, 0xD0, 0x00,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_big_counter() {
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x1F, 0x01, 0x01, 0x01, 0x06, 0x01,
        ]);
        let var_bind = VarBind::with_value(name, VarValue::BigCounter(687817183));

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x13, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x1F, 0x01, 0x01, 0x01, 0x06,
            0x01, 0x46, 0x04, 0x28, 0xFF, 0x41, 0xDF,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_no_such_object() {
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x50, 0x00, 0x01]);
        let var_bind = VarBind::with_value(name, VarValue::NoSuchObject);

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x50, 0x00, 0x01, 0x80, 0x00,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_no_such_instance() {
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x01]);
        let var_bind = VarBind::with_value(name, VarValue::NoSuchInstance);

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = [
            0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x01, 0x81, 0x00,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_encodes_end_of_mib_view() {
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x06, 0x03, 0x10, 0x01, 0x05, 0x02, 0x01, 0x06, 0x09, 0x76,
            0x69, 0x65, 0x77, 0x43, 0x6F, 0x6D, 0x6D, 0x32, 0x08, 0x01, 0x03, 0x06, 0x01, 0x02,
            0x01, 0x01, 0x04,
        ]);
        let var_bind = VarBind::with_value(name, VarValue::EndOfMibView);

        let encoded_var_bind = yasna::construct_der(|writer| var_bind.encode(writer));
        let expected = vec![
            0x30, 0x22, 0x06, 0x1E, 0x2B, 0x06, 0x01, 0x06, 0x03, 0x10, 0x01, 0x05, 0x02, 0x01,
            0x06, 0x09, 0x76, 0x69, 0x65, 0x77, 0x43, 0x6F, 0x6D, 0x6D, 0x32, 0x08, 0x01, 0x03,
            0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x82, 0x00,
        ];

        assert_eq!(encoded_var_bind, expected);
    }

    #[test]
    fn it_decodes_int() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x0D, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00, 0x02, 0x01,
            0x4C,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::Int(76));

        Ok(())
    }

    #[test]
    fn it_decodes_string() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x1A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x04, 0x0E,
            0x64, 0x61, 0x76, 0x69, 0x64, 0x73, 0x2D, 0x6D, 0x62, 0x70, 0x2E, 0x6C, 0x61, 0x6E,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::String(b"davids-mbp.lan".to_vec()));

        Ok(())
    }

    #[test]
    fn it_decodes_oid() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x18, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x03, 0x01, 0x02,
            0x01, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x01, 0x02,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x03, 0x01, 0x02, 0x01,
        ]);
        let oid =
            ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x01, 0x02]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::ObjectId(oid));

        Ok(())
    }

    #[test]
    fn it_decodes_ip() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x15, 0x06, 0x0D, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x04, 0x14, 0x01, 0x01, 0x7F,
            0x00, 0x00, 0x01, 0x40, 0x04, 0x7F, 0x00, 0x00, 0x01,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x04, 0x14, 0x01, 0x01, 0x7F, 0x00, 0x00, 0x01,
        ]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::IpAddress([127, 0, 0, 1]));

        Ok(())
    }

    #[test]
    fn it_decodes_counter() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01,
            0x41, 0x04, 0x28, 0xD6, 0x2F, 0x62,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01,
        ]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::Counter(685125474));

        Ok(())
    }

    #[test]
    fn it_decodes_unsigned_int() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01,
            0x42, 0x04, 0x28, 0xD6, 0x2F, 0x62,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0A, 0x01,
        ]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::UnsignedInt(685125474));

        Ok(())
    }

    #[test]
    fn it_decodes_time_ticks() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x0F, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x03,
            0x0A, 0x9E, 0xC6,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::TimeTicks(696006));

        Ok(())
    }

    #[test]
    fn it_decodes_time_opaque() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x16, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x8F, 0x65, 0x0A, 0x01, 0x06,
            0x01, 0x44, 0x07, 0x9F, 0x78, 0x04, 0x3F, 0xE3, 0xD0, 0x00,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0x7E5, 0x0A, 0x01, 0x06, 0x01,
        ]);

        assert_eq!(var_bind.name, name);
        assert_eq!(
            var_bind.value,
            VarValue::Opaque(vec![0x9F, 0x78, 0x04, 0x3F, 0xE3, 0xD0, 0x00])
        );

        Ok(())
    }

    #[test]
    fn it_decodes_big_counter() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x13, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x1F, 0x01, 0x01, 0x01, 0x06,
            0x01, 0x46, 0x04, 0x28, 0xFF, 0x41, 0xDF,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x1F, 0x01, 0x01, 0x01, 0x06, 0x01,
        ]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::BigCounter(687817183));

        Ok(())
    }

    #[test]
    fn it_decodes_no_such_object() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x50, 0x00, 0x01, 0x80, 0x00,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x50, 0x00, 0x01]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::NoSuchObject);

        Ok(())
    }

    #[test]
    fn it_decodes_no_such_instance() -> ASN1Result<()> {
        let encoded_var_bind = [
            0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x01, 0x81, 0x00,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[0x01, 0x03, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x01]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::NoSuchInstance);

        Ok(())
    }

    #[test]
    fn it_decodes_end_of_mib_view() -> ASN1Result<()> {
        let encoded_var_bind = vec![
            0x30, 0x22, 0x06, 0x1E, 0x2B, 0x06, 0x01, 0x06, 0x03, 0x10, 0x01, 0x05, 0x02, 0x01,
            0x06, 0x09, 0x76, 0x69, 0x65, 0x77, 0x43, 0x6F, 0x6D, 0x6D, 0x32, 0x08, 0x01, 0x03,
            0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x82, 0x00,
        ];
        let var_bind = yasna::parse_ber(&encoded_var_bind, VarBind::decode)?;
        let name = ObjectIdent::from_slice(&[
            0x01, 0x03, 0x06, 0x01, 0x06, 0x03, 0x10, 0x01, 0x05, 0x02, 0x01, 0x06, 0x09, 0x76,
            0x69, 0x65, 0x77, 0x43, 0x6F, 0x6D, 0x6D, 0x32, 0x08, 0x01, 0x03, 0x06, 0x01, 0x02,
            0x01, 0x01, 0x04,
        ]);

        assert_eq!(var_bind.name, name);
        assert_eq!(var_bind.value, VarValue::EndOfMibView);

        Ok(())
    }

    #[test]
    fn read_oid_returns_oid() {
        let name = [0x06, 0x04, 0x2A, 0x81, 0x00, 0x01];
        let result = yasna::parse_ber(&name, VarBind::read_oid);

        assert_eq!(
            result,
            Ok(ObjectIdent::from_slice(&[0x01, 0x02, 0x80, 0x01]))
        );
    }

    #[test]
    fn read_oid_returns_invalid_error_when_not_oid_tag() {
        let int = [0x02, 0x03, 0x01, 0x00, 0x01];
        let result = yasna::parse_ber(&int, VarBind::read_oid);

        assert_eq!(result, Err(ASN1Error::new(ASN1ErrorKind::Invalid)));
    }

    #[test]
    fn read_oid_returns_invalid_error_when_oid_is_empty() {
        let int = [0x06, 0x00];
        let result = yasna::parse_ber(&int, VarBind::read_oid);

        assert_eq!(result, Err(ASN1Error::new(ASN1ErrorKind::Invalid)));
    }

    #[test]
    fn read_oid_returns_invalid_error_when_oid_last_byte_significant_bit_set() {
        let int = [0x06, 0x02, 0x01, 0x80];
        let result = yasna::parse_ber(&int, VarBind::read_oid);

        assert_eq!(result, Err(ASN1Error::new(ASN1ErrorKind::Invalid)));
    }
}
