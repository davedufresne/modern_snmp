use crate::{
    pos_finder::PosFinder, LocalizedKey, Md5, SecurityError, SecurityParams, SecurityResult, Sha1,
    AUTH_PARAMS_LEN, AUTH_PARAMS_PLACEHOLDER,
};
use hmac::SimpleHmac;
use md5::digest::{core_api::BlockSizeUser, Digest as DigestTrait, Mac};
use std::ops::Range;

// Duration in seconds.
const TIME_WINDOW: u32 = 150;

/// Convenience wrapper around digest traits. Useful as trait bound where a digest algorithm is needed.
pub trait Digest: DigestTrait + BlockSizeUser + Clone {}
impl Digest for Md5 {}
impl Digest for Sha1 {}

/// Authentication key used to check data integrity and data origin.
///
/// It is constructed from a [Localizedkey](struct.LocalizedKey.html) and parameterized to use
/// various authentication protocols.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AuthKey<'a, D> {
    localized_key: LocalizedKey<'a, D>,
}

impl<'a, D: 'a> AuthKey<'a, D> {
    /// Constructs a new `AuthKey` using a localized key.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::{AuthKey, LocalizedSha1Key};
    ///
    /// # let passwd = b"1234";
    /// # let engine_id = b"1234";
    /// let localized_key = LocalizedSha1Key::new(passwd, engine_id);
    /// let auth_key = AuthKey::new(localized_key);
    /// ```
    pub fn new(localized_key: LocalizedKey<'a, D>) -> Self {
        Self { localized_key }
    }

    // Returns the security parameters and authentication parameters ranges of an SNMP message.
    fn params_ranges(msg: &[u8]) -> SecurityResult<(Range<usize>, Range<usize>)> {
        let mut pos_finder = PosFinder::new(msg);

        pos_finder.step_into_seq()?; // Message sequence
        pos_finder.skip_int()?; // Version
        pos_finder.skip_seq()?; // Header data
                                // Security parameters as octet string
        let security_params_range = pos_finder.step_into_octet_str()?;

        let auth_params_range = Self::find_auth_params_range(&mut pos_finder)
            .map_err(|_| SecurityError::MalformedSecurityParams)?;

        let auth_params_len = auth_params_range.end - auth_params_range.start;
        if auth_params_len != AUTH_PARAMS_LEN {
            return Err(SecurityError::WrongAuthParams);
        }

        Ok((security_params_range, auth_params_range))
    }

    fn find_auth_params_range(pos_finder: &mut PosFinder) -> SecurityResult<Range<usize>> {
        pos_finder.step_into_seq()?; // Security parameters
        pos_finder.skip_octet_str()?; // Authoritative engine ID
        pos_finder.skip_int()?; // Authoritative engine boots
        pos_finder.skip_int()?; // Authoritative engine time
        pos_finder.skip_octet_str()?; // Username

        pos_finder.step_into_octet_str() // Authentication parameters
    }

    fn validate_timeliness(
        security_params: &SecurityParams,
        local_engine_id: &[u8],
        local_engine_boots: u32,
        local_engine_time: u32,
    ) -> SecurityResult<()> {
        if local_engine_boots >= SecurityParams::ENGINE_BOOTS_MAX {
            return Err(SecurityError::NotInTimeWindow);
        }

        let is_authoritative_engine = security_params.engine_id() == local_engine_id;
        if is_authoritative_engine {
            Self::validate_timeliness_for_authoritative(
                security_params,
                local_engine_boots,
                local_engine_time,
            )?;
        } else {
            Self::validate_timeliness_for_non_authoritative(
                security_params,
                local_engine_boots,
                local_engine_time,
            )?;
        }

        Ok(())
    }

    fn validate_timeliness_for_authoritative(
        security_params: &SecurityParams,
        local_engine_boots: u32,
        local_engine_time: u32,
    ) -> SecurityResult<()> {
        if security_params.engine_boots() != local_engine_boots {
            return Err(SecurityError::NotInTimeWindow);
        }

        let time_diff = security_params.engine_time().abs_diff(local_engine_time);
        if time_diff > TIME_WINDOW {
            return Err(SecurityError::NotInTimeWindow);
        }

        Ok(())
    }

    fn validate_timeliness_for_non_authoritative(
        security_params: &SecurityParams,
        local_engine_boots: u32,
        local_engine_time: u32,
    ) -> SecurityResult<()> {
        if security_params.engine_boots() < local_engine_boots {
            return Err(SecurityError::NotInTimeWindow);
        }

        if security_params.engine_boots() == local_engine_boots
            && Self::less_than_over(
                TIME_WINDOW,
                security_params.engine_time(),
                local_engine_time,
            )
        {
            return Err(SecurityError::NotInTimeWindow);
        }

        Ok(())
    }

    fn less_than_over(amount: u32, lhs: u32, rhs: u32) -> bool {
        if lhs > rhs {
            return false;
        }
        rhs - lhs > amount
    }
}

impl<'a, D: 'a> AuthKey<'a, D>
where
    D: Digest,
{
    /// Authenticates an incoming SNMP message.
    ///
    /// The timeliness check is always preformed when authentication is requested. If the
    /// authentication and the timeliness validation succeed, a security subsystem would update its
    /// local notion of engine boots, engine time and latest received engine time for the
    /// corresponding SNMP engine ID.
    ///
    /// # Arguments
    ///
    /// * `msg` - The SNMP message to authenticate
    /// * `local_engine_id` - The authoritative engine ID
    /// * `local_engine_boots` - The local notion of the authoritative engine boots
    /// * `local_engine_time` - The local notion of the authoritative engine time
    ///
    /// # Errors
    ///
    /// If the message is not properly formed a result with
    /// [MalformedMsg](enum.SecurityError.html#variant.MalformedMsg) error is returned.
    ///
    /// A [MalformedSecurityParams](enum.SecurityError.html#variant.MalformedSecurityParams) error
    /// result is returned if the security parameters are not properly formed.
    ///
    /// If the message could not be authenticated because the authentication parameters don't
    /// match the digest, a result with
    /// [WrongAuthParams](enum.SecurityError.html#variant.WrongAuthParams) error is returned.
    ///
    /// If the timeliness validation fails a result with
    /// [NotInTimeWindow](enum.SecurityError.html#variant.NotInTimeWindow) is returned. Timeliness
    /// validation will fail if `local_engine_boots` or `local_engine_time` is less than `0`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use snmp_usm::{LocalizedKey, Sha1AuthKey};
    ///
    /// # let mut in_msg = [];
    /// # let engine_id = [];
    /// # let engine_boots = 0;
    /// # let engine_time = 0;
    /// let localized_key = LocalizedKey::new(b"password", b"engine_id");
    /// let key = Sha1AuthKey::new(localized_key);
    /// key.auth_in_msg(&mut in_msg, &engine_id, engine_boots, engine_time);
    /// ```
    pub fn auth_in_msg(
        &self,
        msg: &mut [u8],
        local_engine_id: &[u8],
        local_engine_boots: u32,
        local_engine_time: u32,
    ) -> SecurityResult<()> {
        let (security_params_range, auth_params_range) = Self::params_ranges(msg)?;

        let mut saved_auth_params: [u8; AUTH_PARAMS_LEN] = [0x0; AUTH_PARAMS_LEN];
        saved_auth_params.copy_from_slice(&msg[auth_params_range.start..auth_params_range.end]);

        msg[auth_params_range.start..auth_params_range.end]
            .copy_from_slice(&AUTH_PARAMS_PLACEHOLDER);
        let auth_params = self.hmac(msg);
        if saved_auth_params != auth_params[..] {
            return Err(SecurityError::WrongAuthParams);
        }

        msg[auth_params_range].copy_from_slice(&saved_auth_params);

        let security_params = SecurityParams::decode(&msg[security_params_range])?;
        Self::validate_timeliness(
            &security_params,
            local_engine_id,
            local_engine_boots,
            local_engine_time,
        )?;

        Ok(())
    }

    /// Authenticates an outgoing SNMP message.
    ///
    /// # Errors
    ///
    /// If the message is not properly formed a result with
    /// [MalformedMsg](enum.SecurityError.html#variant.MalformedMsg) error is returned.
    ///
    /// If the security parameters are not properly formed a result with
    /// [MalformedSecurityParams](enum.SecurityError.html#variant.MalformedSecurityParams) error is
    /// returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use snmp_usm::{LocalizedKey, Sha1AuthKey};
    ///
    /// # fn main() -> snmp_usm::SecurityResult<()> {
    /// # let mut out_msg = [];
    /// let localized_key = LocalizedKey::new(b"password", b"engine_id");
    /// let key = Sha1AuthKey::new(localized_key);
    /// key.auth_out_msg(&mut out_msg)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn auth_out_msg(&self, msg: &mut [u8]) -> SecurityResult<()> {
        let (_, auth_params_range) = Self::params_ranges(msg)?;
        let auth_params = self.hmac(msg);
        msg[auth_params_range].copy_from_slice(&auth_params);

        Ok(())
    }

    // Calculates the HMAC of the SNMP message.
    fn hmac(&self, msg: &[u8]) -> Vec<u8> {
        let mut mac = SimpleHmac::<D>::new_from_slice(self.localized_key.bytes()).unwrap();

        mac.update(msg);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        bytes[0..AUTH_PARAMS_LEN].to_vec()
    }
}
