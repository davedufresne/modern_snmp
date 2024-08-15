use super::PrivKey;
use crate::{LocalizedKey, SecurityError, SecurityParams, SecurityResult, WithLocalizedKey};
use aes::cipher::{AsyncStreamCipher, IvSizeUser, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use cfb_mode::{Decryptor, Encryptor};

/// Privacy key used for AES encryption.
///
/// It is constructed from a [Localizedkey](struct.LocalizedKey.html).
///
/// Authentication must always be performed when encryption is requested.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AesPrivKey<'a, D, const BITS: usize> {
    localized_key: LocalizedKey<'a, D>,
}

impl<'a, D, const BITS: usize> AesPrivKey<'a, D, BITS> {
    fn iv(&self, engine_boots: u32, engine_time: u32, salt: &[u8]) -> Vec<u8> {
        let mut iv = Vec::with_capacity(match BITS {
            128 => <Encryptor<Aes128> as IvSizeUser>::iv_size(),
            192 => <Encryptor<Aes192> as IvSizeUser>::iv_size(),
            256 => <Encryptor<Aes256> as IvSizeUser>::iv_size(),
            _ => unreachable!("Invalid number of bits"),
        });

        iv.extend_from_slice(&engine_boots.to_be_bytes());
        iv.extend_from_slice(&engine_time.to_be_bytes());
        iv.extend_from_slice(salt);

        iv
    }

    fn key(&self) -> &[u8] {
        let key = self.localized_key.bytes_full();

        &key[..(BITS / 8)]
    }
}

impl<'a, D, const BITS: usize> PrivKey for AesPrivKey<'a, D, BITS> {
    type Salt = u64;

    // Encrypts a scoped PDU using AES.
    fn encrypt(
        &self,
        mut scoped_pdu: Vec<u8>,
        security_params: &SecurityParams,
        salt: Self::Salt,
    ) -> (Vec<u8>, Vec<u8>) {
        let salt = salt.to_be_bytes();
        let iv = self.iv(
            security_params.engine_boots(),
            security_params.engine_time(),
            &salt,
        );

        match BITS {
            128 => Encryptor::<Aes128>::new_from_slices(self.key(), &iv)
                .unwrap()
                .encrypt(&mut scoped_pdu),
            192 => Encryptor::<Aes192>::new_from_slices(self.key(), &iv)
                .unwrap()
                .encrypt(&mut scoped_pdu),
            256 => Encryptor::<Aes256>::new_from_slices(self.key(), &iv)
                .unwrap()
                .encrypt(&mut scoped_pdu),
            _ => unreachable!("Invalid number of bits"),
        };

        (scoped_pdu, salt.to_vec())
    }

    // Decrypts a scoped PDU that was encrypted using AES.
    fn decrypt(
        &self,
        mut encrypted_scoped_pdu: Vec<u8>,
        security_params: &SecurityParams,
    ) -> SecurityResult<Vec<u8>> {
        let iv = self.iv(
            security_params.engine_boots(),
            security_params.engine_time(),
            security_params.priv_params(),
        );

        match BITS {
            128 => Decryptor::<Aes128>::new_from_slices(self.key(), &iv)
                .map_err(|_| SecurityError::DecryptError)?
                .decrypt(&mut encrypted_scoped_pdu),
            192 => Decryptor::<Aes192>::new_from_slices(self.key(), &iv)
                .map_err(|_| SecurityError::DecryptError)?
                .decrypt(&mut encrypted_scoped_pdu),
            256 => Decryptor::<Aes256>::new_from_slices(self.key(), &iv)
                .map_err(|_| SecurityError::DecryptError)?
                .decrypt(&mut encrypted_scoped_pdu),
            _ => unreachable!("Invalid number of bits"),
        };

        Ok(encrypted_scoped_pdu)
    }
}

impl<'a, D, const BITS: usize> WithLocalizedKey<'a, D> for AesPrivKey<'a, D, BITS> {
    fn with_localized_key(localized_key: LocalizedKey<'a, D>) -> Self {
        match BITS {
            128 | 192 | 256 => Self { localized_key },
            _ => panic!("Invalid number of bits"),
        }
    }
}
