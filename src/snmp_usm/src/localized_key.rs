use md5::digest::{Digest, FixedOutputReset};
use std::marker::PhantomData;

// Password to key algorithm:
//
// 1- Forming a string of length 1,048,576 octets by repeating the value of the password as often
//    as necessary, truncating accordingly, and using the resulting string as the input to the
//    hashing algorithm. The resulting digest, termed "digest1", is used in the next step.
// 2- A second string is formed by concatenating digest1, the SNMP engine's snmpEngineID value, and
//    digest1. This string is used as input to the hashing algorithm.
//
// See RFC 3414 for more details.

const ONE_MEGABYTE: usize = 1_048_576;
const PASSWD_BUF_LEN: usize = 64;
const AES_256_KEY_LEN: usize = 32;

/// Localized key used to verify the identity of users, verify the integrity of messages and
/// encrypt messages.
///
/// `LocalizedKey` is parametrize to use different message-digest algorithms. A key is unique for
/// a user at an authoritative SNMP engine. It's usually cached by the security subsystem.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct LocalizedKey<'a, D> {
    bytes: Vec<u8>,
    _digest_type: PhantomData<&'a D>,
    orig_len: usize,
}

impl<'a, D> LocalizedKey<'a, D> {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.orig_len]
    }

    pub(crate) fn bytes_full(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'a, D> LocalizedKey<'a, D>
where
    D: Digest + FixedOutputReset + Default + Clone,
{
    /// Creates a key from a user password and an authoritative engine ID.
    ///
    /// The password should be at least 8 characters in length.
    ///
    /// # Panics
    ///
    /// Panics if `passwd` has length 0.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::LocalizedMd5Key;
    ///
    /// let key = LocalizedMd5Key::new(b"password", b"engine_id");
    /// ```
    pub fn new(passwd: &[u8], engine_id: &[u8]) -> Self {
        let mut bytes = vec![];

        let mut len = None;

        while bytes.len() < AES_256_KEY_LEN {
            let mut data =
                Self::key_from_passwd(if bytes.is_empty() { passwd } else { &bytes }, engine_id);

            if len.is_none() {
                len = Some(data.len())
            }

            bytes.append(&mut data);
        }

        Self {
            bytes,
            _digest_type: PhantomData,
            orig_len: len.expect("No bytes generated"),
        }
    }

    // Returns a localized key from a user password and an authoritative engine ID.
    fn key_from_passwd(passwd: &[u8], engine_id: &[u8]) -> Vec<u8> {
        assert!(
            !passwd.is_empty(),
            "password for localized key cannot be empty"
        );

        let mut passwd_buf = vec![0; PASSWD_BUF_LEN];
        let mut passwd_index = 0;
        let passwd_len = passwd.len();
        let mut hashing_fn = D::default();

        for _ in (0..ONE_MEGABYTE).step_by(PASSWD_BUF_LEN) {
            for byte in passwd_buf.iter_mut() {
                *byte = passwd[passwd_index % passwd_len];
                passwd_index += 1;
            }

            Digest::update(&mut hashing_fn, &passwd_buf);
        }

        let key = hashing_fn.finalize_reset();
        passwd_buf.clear();
        passwd_buf.extend_from_slice(&key);
        passwd_buf.extend_from_slice(engine_id);
        passwd_buf.extend_from_slice(&key);

        Digest::update(&mut hashing_fn, &passwd_buf);
        hashing_fn.finalize().to_vec()
    }
}

/// Trait implemented by types created with a localized key.
///
/// This trait helps simplify code having to create types generically with a localized key.
pub trait WithLocalizedKey<'a, D> {
    /// Constructs a new type with a localized key.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::{DesPrivKey, LocalizedSha1Key, WithLocalizedKey};
    ///
    /// # let passwd = b"12345678";
    /// # let engine_id = b"1234";
    /// let localized_key = LocalizedSha1Key::new(passwd, engine_id);
    /// let priv_key = DesPrivKey::with_localized_key(localized_key);
    /// ```
    fn with_localized_key(localized_key: LocalizedKey<'a, D>) -> Self;
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::Md5;
    use sha1::Sha1;

    #[test]
    fn it_constructs_localized_key_with_md5() {
        let engine_id = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x02];
        let result = LocalizedKey::<Md5>::new(b"maplesyrup", &engine_id);

        let expected = [
            0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f, 0x89, 0x64, 0xc2, 0x93, 0x07, 0x87,
            0xd8, 0x2b,
        ];
        assert_eq!(result.bytes(), expected);
    }

    #[test]
    fn it_constructs_localized_key_with_sha1() {
        let engine_id = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x02];
        let result = LocalizedKey::<Sha1>::new(b"maplesyrup", &engine_id);

        let expected = [
            0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23, 0x5f, 0xc7, 0x15, 0x1f,
            0x12, 0x84, 0x97, 0xb3, 0x8f, 0x3f,
        ];
        assert_eq!(result.bytes(), expected);
    }

    #[test]
    #[should_panic]
    fn it_panics_with_empty_passwd() {
        let engine_id = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x02];
        LocalizedKey::<Sha1>::new(b"", &engine_id);
    }
}
