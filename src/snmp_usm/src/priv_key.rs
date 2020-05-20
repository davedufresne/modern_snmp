mod aes128_priv_key;
mod des_priv_key;

use crate::{SecurityParams, SecurityResult};
pub use aes128_priv_key::Aes128PrivKey;
pub use des_priv_key::DesPrivKey;

const PRIV_KEY_LEN: usize = 16;

/// A trait for privacy keys.
///
/// Privacy keys are used to encrypt scoped PDUs.
pub trait PrivKey {
    /// The type of the "salt" used for encryption.
    type Salt;

    /// Encrypts a scoped PDU in place.
    ///
    /// It returns the encrypted scoped PDU and the "salt" that was used for the encryption. This
    /// "salt" must be placed in the privacy parameters to enable the receiving entity to compute
    /// the correct IV and to decrypt the scoped PDU.
    ///
    /// # Arguments
    ///
    /// * `scoped_pdu` - The encoded scoped PDU
    /// * `security_params` - Security parameters related to the scoped PDU to encrypt
    /// * `salt` - "Salt" integer that as to be modified after being used to encrypt a message. How
    ///   exactly the value of the "salt" (and thus of the IV) varies, is an implementation issue,
    ///   as long as the measures are taken to avoid producing a duplicate IV
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_usm::{LocalizedSha1Key, SecurityParams};
    /// use snmp_usm::{Aes128PrivKey, PrivKey};
    ///
    /// # let scoped_pdu = b"1234".to_vec();
    /// # let security_params = SecurityParams::new();
    /// # let localized_key = LocalizedSha1Key::new(b"1234", b"1234");
    /// let priv_key = Aes128PrivKey::new(localized_key);
    /// let (encrypted_scoped_pdu, salt) = priv_key.encrypt(scoped_pdu, &security_params, 0);
    /// ```
    fn encrypt(
        &self,
        scoped_pdu: Vec<u8>,
        security_params: &SecurityParams,
        salt: Self::Salt,
    ) -> (Vec<u8>, Vec<u8>);

    /// Decrypts an encrypted scoped PDU in place.
    ///
    /// # Arguments
    ///
    /// * `encrypted_scoped_pdu` - The encrypted scoped PDU
    /// * `security_params` - Security parameters related to the scoped PDU to decrypt
    ///
    /// # Errors
    ///
    /// If the decryption failed a result with
    /// [DecryptError](enum.SecurityError.html#variant.DecryptError) error is returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use snmp_usm::{LocalizedMd5Key, SecurityParams};
    /// use snmp_usm::{DesPrivKey, PrivKey};
    ///
    /// # fn main() -> snmp_usm::SecurityResult<()> {
    /// # let encrypted_scoped_pdu = b"1234".to_vec();
    /// # let security_params = SecurityParams::new();
    /// # let localized_key = LocalizedMd5Key::new(b"1234", b"1234");
    /// let priv_key = DesPrivKey::new(localized_key);
    /// let decrypted_scoped_pdu = priv_key.decrypt(encrypted_scoped_pdu, &security_params)?;
    /// # Ok(())
    /// # }
    /// ```
    fn decrypt(
        &self,
        encrypted_scoped_pdu: Vec<u8>,
        security_params: &SecurityParams,
    ) -> SecurityResult<Vec<u8>>;
}
