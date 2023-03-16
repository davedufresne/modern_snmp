use crate::{SecurityError, SecurityResult};
use std::ops::Range;
use yasna::{tags, Tag, TagClass};

const TAG_CLASSES: [TagClass; 4] = [
    TagClass::Universal,
    TagClass::Application,
    TagClass::ContextSpecific,
    TagClass::Private,
];

const TAG_CLASS_POS: u8 = 6;
const TAG_TYPE_POS: u8 = 5;
const TAG_NUM_MASK: u8 = 0b0001_1111;
const INDEFINITE_LEN: u8 = 0x80;
const RESERVED_FORM_LEN: u8 = 0xFF;
const LONG_FORM_LEN_MASK: u8 = 0x7F;
const INTEGER_BASE: usize = 256;

// Struct used to find a precise position in an encoded SNMP message. It doesn't support the
// following encoding:
//
// * High tag number.
// * Indefinite length.
// * Long form length larger than usize::MAX
pub struct PosFinder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PosFinder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn skip_int(&mut self) -> SecurityResult<()> {
        self.skip_field_type(tags::TAG_INTEGER, false)
    }

    pub fn skip_octet_str(&mut self) -> SecurityResult<()> {
        self.skip_field_type(tags::TAG_OCTETSTRING, false)
    }

    pub fn step_into_octet_str(&mut self) -> SecurityResult<Range<usize>> {
        let range = self.step_into_field_type(tags::TAG_OCTETSTRING, false)?;
        Ok(range)
    }

    pub fn skip_seq(&mut self) -> SecurityResult<()> {
        self.skip_field_type(tags::TAG_SEQUENCE, true)
    }

    pub fn step_into_seq(&mut self) -> SecurityResult<Range<usize>> {
        let range = self.step_into_field_type(tags::TAG_SEQUENCE, true)?;
        Ok(range)
    }

    fn skip_tag_type(&mut self, tag: Tag, is_constructed: bool) -> SecurityResult<()> {
        let (_, is_constr) = self.read_tag_type(tag)?;
        if is_constructed != is_constr {
            return Err(SecurityError::MalformedMsg);
        }

        Ok(())
    }

    fn skip_field_type(&mut self, tag: Tag, is_constructed: bool) -> SecurityResult<()> {
        self.skip_tag_type(tag, is_constructed)?;
        self.pos += self.read_len()?;

        Ok(())
    }

    fn step_into_field_type(
        &mut self,
        tag: Tag,
        is_constructed: bool,
    ) -> SecurityResult<Range<usize>> {
        self.skip_tag_type(tag, is_constructed)?;
        let len = self.read_len()?;
        let end = self.pos + len;

        Ok(self.pos..end)
    }

    fn read_tag(&mut self) -> SecurityResult<(Tag, bool)> {
        let tag_byte = self.read_u8()?;
        let tag_number = tag_byte & TAG_NUM_MASK;
        // High tag numbers are not supported.
        if tag_number == TAG_NUM_MASK {
            return Err(SecurityError::MalformedMsg);
        }

        let tag_class = TAG_CLASSES[(tag_byte >> TAG_CLASS_POS) as usize];
        let tag_number = tag_number as u64;

        let tag = Tag {
            tag_class,
            tag_number,
        };
        let is_constructed = (tag_byte >> TAG_TYPE_POS) & 1 == 1;

        Ok((tag, is_constructed))
    }

    // Doesn't support indefinite length and long form length larger than usize::MAX.
    fn read_len(&mut self) -> SecurityResult<usize> {
        let len_byte = self.read_u8()?;

        if len_byte == RESERVED_FORM_LEN {
            return Err(SecurityError::MalformedMsg);
        }

        if len_byte == INDEFINITE_LEN {
            return Err(SecurityError::MalformedMsg);
        }

        let is_short_form = (len_byte >> 7) == 0;
        let len = if is_short_form {
            len_byte as usize
        } else {
            let mut len: usize = 0;
            for _ in 0..(len_byte & LONG_FORM_LEN_MASK) {
                let part = len
                    .checked_mul(INTEGER_BASE)
                    .ok_or(SecurityError::MalformedMsg)?;
                len = part + self.read_u8()? as usize;
            }

            len
        };

        if self.pos + len > self.buf.len() {
            return Err(SecurityError::MalformedMsg);
        }

        Ok(len)
    }

    fn read_tag_type(&mut self, tag: Tag) -> SecurityResult<(Tag, bool)> {
        let (read_tag, is_constructed) = self.read_tag()?;
        if tag != read_tag {
            return Err(SecurityError::MalformedMsg);
        }

        Ok((tag, is_constructed))
    }

    fn read_u8(&mut self) -> SecurityResult<u8> {
        if self.pos >= self.buf.len() {
            return Err(SecurityError::MalformedMsg);
        }

        let byte = self.buf[self.pos];
        self.pos += 1;
        Ok(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yasna::tags;

    #[test]
    fn it_skips_int() {
        let int = [0x02, 0x03, 0x01, 0x00, 0x01];
        let mut finder = PosFinder::new(&int);
        finder.skip_int().unwrap();

        assert_eq!(finder.pos, int.len());
    }

    #[test]
    fn it_skips_octet_str() {
        let octet_str = [0x04, 0x03, 0x01, 0x02, 0x03];
        let mut finder = PosFinder::new(&octet_str);
        finder.skip_octet_str().unwrap();

        assert_eq!(finder.pos, octet_str.len());
    }

    #[test]
    fn it_steps_into_octet_str() {
        let octet_str = [0x04, 0x03, 0x01, 0x02, 0x03];
        let mut finder = PosFinder::new(&octet_str);
        let result = finder.step_into_octet_str().unwrap();

        assert_eq!(finder.pos, 2);
        assert_eq!(result, 2..5);
    }

    #[test]
    fn it_skips_seq() {
        let seq = [0x30, 0x03, 0x01, 0x02, 0x03];
        let mut finder = PosFinder::new(&seq);
        finder.skip_seq().unwrap();

        assert_eq!(finder.pos, seq.len());
    }

    #[test]
    fn it_steps_into_seq() {
        let seq = [0x30, 0x03, 0x01, 0x02, 0x03];
        let mut finder = PosFinder::new(&seq);
        let result = finder.step_into_seq().unwrap();

        assert_eq!(finder.pos, 2);
        assert_eq!(result, 2..5);
    }

    #[test]
    fn it_returns_invalid_error_for_high_tag_num() {
        let time_of_day = [0x1F, 0x20, 0x06, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30];
        let mut finder = PosFinder::new(&time_of_day);
        let result = finder.read_tag();

        assert_eq!(result, Err(SecurityError::MalformedMsg));
    }

    #[test]
    fn it_returns_invalid_error_for_invalid_short_len() {
        let octet_str = [0x04, 0x04, 0x01, 0x02, 0x03];
        let mut finder = PosFinder::new(&octet_str);
        finder.read_tag().unwrap();
        let result = finder.read_len();

        assert_eq!(result, Err(SecurityError::MalformedMsg));
    }

    #[test]
    fn it_returns_invalid_error_for_invalid_long_len() {
        let long_len = [0x82, 0x01, 0x01, 0x00];
        let mut finder = PosFinder::new(&long_len);
        let result = finder.read_len();

        assert_eq!(result, Err(SecurityError::MalformedMsg));
    }

    #[test]
    fn it_returns_invalid_error_for_indefinite_len() {
        let indefinite_len = [0x80, 0x01, 0x00, 0x00];
        let mut finder = PosFinder::new(&indefinite_len);
        let result = finder.read_len();

        assert_eq!(result, Err(SecurityError::MalformedMsg));
    }

    #[test]
    fn it_returns_invalid_error_for_len_larger_than_usize_max() {
        let very_long_len = [0x89, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut finder = PosFinder::new(&very_long_len);
        let result = finder.read_len();

        assert_eq!(result, Err(SecurityError::MalformedMsg));
    }

    #[test]
    fn it_returns_error_for_wrong_tag() {
        let int = [0x02, 0x03, 0x01, 0x00, 0x01];
        let mut finder = PosFinder::new(&int);
        let result = finder.read_tag_type(tags::TAG_OCTETSTRING);

        assert_eq!(result, Err(SecurityError::MalformedMsg));
    }

    #[test]
    fn it_returns_error_when_reading_end_of_buf() {
        let buf = [];
        let mut finder = PosFinder::new(&buf);
        let result = finder.read_u8();

        assert_eq!(result, Err(SecurityError::MalformedMsg));
    }
}
