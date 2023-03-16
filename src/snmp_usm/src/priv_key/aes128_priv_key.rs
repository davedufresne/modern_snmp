use super::{PrivKey, PRIV_KEY_LEN};
use crate::{LocalizedKey, SecurityError, SecurityParams, SecurityResult, WithLocalizedKey};
use aes::cipher::{AsyncStreamCipher, IvSizeUser, KeyIvInit};
use aes::Aes128;
use cfb_mode::{Decryptor, Encryptor};

type Aes128CfbEnc = Encryptor<Aes128>;
type Aes128CfbDec = Decryptor<Aes128>;

/// Privacy key used for AES-128 encryption.
///
/// It is constructed from a [Localizedkey](struct.LocalizedKey.html).
///
/// Authentication must always be performed when encryption is requested.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Aes128PrivKey<'a, D> {
    localized_key: LocalizedKey<'a, D>,
}

impl<'a, D> Aes128PrivKey<'a, D> {
    fn iv(&self, engine_boots: u32, engine_time: u32, salt: &[u8]) -> Vec<u8> {
        let mut iv = Vec::with_capacity(<Aes128CfbEnc as IvSizeUser>::iv_size());
        iv.extend_from_slice(&engine_boots.to_be_bytes());
        iv.extend_from_slice(&engine_time.to_be_bytes());
        iv.extend_from_slice(&salt);

        iv
    }

    fn key(&self) -> &[u8] {
        let key = self.localized_key.bytes();
        &key[..PRIV_KEY_LEN]
    }
}

impl<'a, D> PrivKey for Aes128PrivKey<'a, D> {
    type Salt = u64;

    // Encrypts a scoped PDU using AES-128.
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
        let encryptor = Aes128CfbEnc::new_from_slices(self.key(), &iv).unwrap();
        encryptor.encrypt(&mut scoped_pdu);

        (scoped_pdu, salt.to_vec())
    }

    // Decrypts a scoped PDU that was encrypted using AES-128.
    fn decrypt(
        &self,
        mut encrypted_scoped_pdu: Vec<u8>,
        security_params: &SecurityParams,
    ) -> SecurityResult<Vec<u8>> {
        let iv = self.iv(
            security_params.engine_boots(),
            security_params.engine_time(),
            &security_params.priv_params(),
        );
        let decryptor = Aes128CfbDec::new_from_slices(self.key(), &iv)
            .map_err(|_| SecurityError::DecryptError)?;
        decryptor.decrypt(&mut encrypted_scoped_pdu);

        Ok(encrypted_scoped_pdu)
    }
}

impl<'a, D> WithLocalizedKey<'a, D> for Aes128PrivKey<'a, D> {
    fn with_localized_key(localized_key: LocalizedKey<'a, D>) -> Self {
        Self { localized_key }
    }
}
