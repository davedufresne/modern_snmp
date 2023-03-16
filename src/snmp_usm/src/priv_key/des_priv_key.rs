use super::{PrivKey, PRIV_KEY_LEN};
use crate::{LocalizedKey, SecurityError, SecurityParams, SecurityResult, WithLocalizedKey};
use block_modes::{block_padding::NoPadding, BlockMode, Cbc, InvalidKeyIvLength};
use des::{
    block_cipher::{generic_array::typenum::Unsigned, BlockCipher, NewBlockCipher},
    Des,
};

type DesCbc = Cbc<Des, NoPadding>;

/// Privacy key used for DES encryption.
///
/// It is constructed from a [Localizedkey](struct.LocalizedKey.html). When decrypting the padding
/// is not removed.
///
/// Authentication must always be performed when encryption is requested.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DesPrivKey<'a, D> {
    localized_key: LocalizedKey<'a, D>,
}

impl<'a, D> DesPrivKey<'a, D> {
    // Returns a DES block cipher.
    fn cipher(&self, salt: &[u8]) -> Result<DesCbc, InvalidKeyIvLength> {
        let des_key_len = <Des as NewBlockCipher>::KeySize::to_usize();
        let key = self.localized_key.bytes();
        let (des_key, pre_iv) = key[..PRIV_KEY_LEN].split_at(des_key_len);

        let iv: Vec<_> = salt
            .iter()
            .zip(pre_iv.iter())
            .map(|(salt, pre_iv)| salt ^ pre_iv)
            .collect();

        DesCbc::new_var(des_key, &iv)
    }

    fn add_padding_space(buf: &mut Vec<u8>) {
        let len = buf.len();
        let block_size = <Des as BlockCipher>::BlockSize::to_usize();

        let rem = len % block_size;
        if rem != 0 {
            let padding_space = block_size - rem;
            buf.resize(len + padding_space, 0);
        }
    }
}

impl<'a, D> PrivKey for DesPrivKey<'a, D> {
    type Salt = u32;

    // Encrypts a scoped PDU using DES.
    fn encrypt(
        &self,
        mut scoped_pdu: Vec<u8>,
        security_params: &SecurityParams,
        salt: Self::Salt,
    ) -> (Vec<u8>, Vec<u8>) {
        let salt = [
            security_params.engine_boots().to_be_bytes(),
            salt.to_be_bytes(),
        ]
        .concat();

        if scoped_pdu.is_empty() {
            return (scoped_pdu, salt);
        }

        let cipher = self.cipher(&salt).unwrap();

        Self::add_padding_space(&mut scoped_pdu);
        let len = scoped_pdu.len();
        cipher.encrypt(&mut scoped_pdu, len).unwrap();

        (scoped_pdu, salt)
    }

    // Decrypts a scoped PDU that was encrypted using DES.
    fn decrypt(
        &self,
        mut encrypted_scoped_pdu: Vec<u8>,
        security_params: &SecurityParams,
    ) -> SecurityResult<Vec<u8>> {
        if encrypted_scoped_pdu.is_empty() {
            return Ok(encrypted_scoped_pdu);
        }

        let salt = security_params.priv_params();
        self.cipher(salt)
            .map_err(|_| SecurityError::DecryptError)?
            .decrypt(&mut encrypted_scoped_pdu)
            .map_err(|_| SecurityError::DecryptError)?;

        Ok(encrypted_scoped_pdu)
    }
}

impl<'a, D> WithLocalizedKey<'a, D> for DesPrivKey<'a, D> {
    fn with_localized_key(localized_key: LocalizedKey<'a, D>) -> Self {
        Self { localized_key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Md5;

    #[test]
    fn it_adds_padding_if_not_multiple_of_block_size() {
        let block_size = <Des as BlockCipher>::BlockSize::to_usize();
        let mut buf = vec![0; block_size + block_size / 2];

        DesPrivKey::<Md5>::add_padding_space(&mut buf);
        assert_eq!(buf.len(), block_size * 2);
    }

    #[test]
    fn it_does_not_add_padding_if_multiple_of_block_size() {
        let block_size = <Des as BlockCipher>::BlockSize::to_usize();
        let mut buf = vec![0; block_size];

        DesPrivKey::<Md5>::add_padding_space(&mut buf);
        assert_eq!(buf.len(), block_size);
    }
}
