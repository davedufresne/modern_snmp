use crate::{Digest, SecurityError, SecurityResult};

/// Security parameters used by the User-based Security Model.
///
/// It contains the necessary information to achieve the following goals:
///
/// * Verification that each received SNMP message has not been modified.
/// * User identity verification.
/// * Detection of received SNMP messages whose time of generation was not recent.
/// * Message encryption.
///
/// Empty security params can be generated using [SecurityParams::new()](#method.new). Additional
/// builder methods allow the security parameters to be changed.
///
/// # Examples
///
/// ```
/// use snmp_usm::{SecurityParams, Sha1};
///
/// let mut security_params = SecurityParams::new();
/// security_params.set_username(b"username")
///     .set_priv_params(b"saltsalt")
///     .set_auth_params_placeholder::<Sha1>();
/// ```
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct SecurityParams {
    engine_id: Vec<u8>,
    engine_boots: u32,
    engine_time: u32,
    username: Vec<u8>,
    auth_params: Vec<u8>,
    priv_params: Vec<u8>,
}

impl SecurityParams {
    /// The largest value for [engine_boots](#method.engine_boots).
    ///
    /// Whenever the local value of `engine_boots` has a value equal to or greater than
    /// 2_147_483_647 an authenticated message always causes an
    /// [NotInTimeWindow](enum.SecurityError.html#variant.NotInTimeWindow) authentication failure.
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_usm::SecurityParams;
    /// assert_eq!(SecurityParams::ENGINE_BOOTS_MAX, 2_147_483_647);
    /// ```
    pub const ENGINE_BOOTS_MAX: u32 = 2_147_483_647;

    /// The largest value for [engine_time](#method.engine_time).
    ///
    /// # Examples
    ///
    /// ```
    /// # use snmp_usm::SecurityParams;
    /// assert_eq!(SecurityParams::ENGINE_TIME_MAX, 2_147_483_647);
    /// ```
    pub const ENGINE_TIME_MAX: u32 = 2_147_483_647;

    /// Alias for [for_discovery](#method.for_discovery).
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns security parameters with a security username of zero-length and an authoritative
    /// engine ID of zero-length.
    ///
    /// The User-based Security Model requires that a discovery process obtains sufficient
    /// information about other SNMP engines in order to communicate with them. Discovery requires
    /// an non-authoritative SNMP engine to learn the authoritative SNMP engine's ID value before
    /// communication may proceed. This function returns security parameters that can be included
    /// in a discovery message.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// let security_params = SecurityParams::for_discovery();
    /// assert_eq!(security_params.username(), b"");
    /// assert_eq!(security_params.engine_id(), b"");
    ///
    /// // A message processing subsystem would set the security parameters of the discovery
    /// // message.
    /// // discovery_msg.set_security_params(&security_params.encode());
    /// ```
    pub fn for_discovery() -> Self {
        Self::default()
    }

    /// Returns the authoritative engine's ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// # let security_params = SecurityParams::for_discovery();
    /// let engine_id = security_params.engine_id();
    /// ```
    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    /// Sets the authoritative engine's ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// let mut security_params = SecurityParams::new();
    /// security_params.set_engine_id(b"engine_id");
    /// assert_eq!(security_params.engine_id(), b"engine_id");
    /// ```
    pub fn set_engine_id(&mut self, engine_id: &[u8]) -> &mut Self {
        self.engine_id.clear();
        self.engine_id.extend_from_slice(engine_id);
        self
    }

    /// Returns the authoritative engine's boots.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// # let security_params = SecurityParams::for_discovery();
    /// let engine_boots = security_params.engine_boots();
    /// ```
    pub fn engine_boots(&self) -> u32 {
        self.engine_boots
    }

    /// Sets the authoritative engine's boots.
    ///
    /// The value should not be larger than
    /// [ENGINE_BOOTS_MAX](#associatedconstant.ENGINE_BOOTS_MAX).
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// let mut security_params = SecurityParams::new();
    /// security_params.set_engine_boots(1);
    /// assert_eq!(security_params.engine_boots(), 1);
    /// ```
    pub fn set_engine_boots(&mut self, engine_boots: u32) -> &mut Self {
        self.engine_boots = engine_boots;
        self
    }

    /// Returns the authoritative engine's time.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// # let security_params = SecurityParams::for_discovery();
    /// let engine_time = security_params.engine_time();
    /// ```
    pub fn engine_time(&self) -> u32 {
        self.engine_time
    }

    /// Sets the authoritative engine's time.
    ///
    /// The value should not be larger than
    /// [ENGINE_TIME_MAX](#associatedconstant.ENGINE_TIME_MAX).
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// let mut security_params = SecurityParams::new();
    /// security_params.set_engine_boots(1);
    /// assert_eq!(security_params.engine_boots(), 1);
    /// ```
    pub fn set_engine_time(&mut self, engine_time: u32) -> &mut Self {
        self.engine_time = engine_time;
        self
    }

    /// Returns the username.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// # let security_params = SecurityParams::for_discovery();
    /// let username = security_params.username();
    /// ```
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    /// Sets the username.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// let mut security_params = SecurityParams::new();
    /// security_params.set_username(b"username");
    /// assert_eq!(security_params.username(), b"username");
    /// ```
    pub fn set_username(&mut self, username: &[u8]) -> &mut Self {
        self.username.clear();
        self.username.extend_from_slice(username);
        self
    }

    // Returns the authentication parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// # let security_params = SecurityParams::for_discovery();
    /// let auth_params = security_params.auth_params();
    /// ```
    pub fn auth_params(&self) -> &[u8] {
        &self.auth_params
    }

    /// Sets the authentication parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// let mut security_params = SecurityParams::new();
    /// security_params.set_auth_params(b"auth_params");
    /// assert_eq!(security_params.auth_params(), b"auth_params");
    /// ```
    pub fn set_auth_params(&mut self, auth_params: &[u8]) -> &mut Self {
        self.auth_params.clear();
        self.auth_params.extend_from_slice(auth_params);
        self
    }

    /// Sets the authentication parameters placeholder.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::{SecurityParams, Sha1};
    ///
    /// let mut security_params = SecurityParams::new();
    /// security_params.set_auth_params_placeholder::<Sha1>();
    /// assert_eq!(security_params.auth_params(), [0x0; 12]);
    /// ```
    pub fn set_auth_params_placeholder<D: Digest>(&mut self) -> &mut Self {
        self.set_auth_params(D::AUTH_PARAMS_PLACEHOLDER);
        self
    }

    /// Returns the privacy parameters.
    ///
    /// They contain the "salt" used in the scoped PDU encryption.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// # let security_params = SecurityParams::for_discovery();
    /// let priv_params = security_params.priv_params();
    /// ```
    pub fn priv_params(&self) -> &[u8] {
        &self.priv_params
    }

    /// Sets the privacy parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// let mut security_params = SecurityParams::new();
    /// security_params.set_priv_params(b"saltsalt");
    /// assert_eq!(security_params.priv_params(), b"saltsalt");
    /// ```
    pub fn set_priv_params(&mut self, priv_params: &[u8]) -> &mut Self {
        self.priv_params.clear();
        self.priv_params.extend_from_slice(priv_params);
        self
    }

    /// Encodes the security parameters.
    ///
    /// A message processing subsystem can add the encoded security parameters to a message as a
    /// byte string.
    ///
    /// # Examples
    ///
    /// ```
    /// use snmp_usm::SecurityParams;
    ///
    /// let security_params = SecurityParams::new();
    /// let encoded_security_params = security_params.encode();
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_bytes(&self.engine_id);
                writer.next().write_u32(self.engine_boots);
                writer.next().write_u32(self.engine_time);
                writer.next().write_bytes(&self.username);
                writer.next().write_bytes(&self.auth_params);
                writer.next().write_bytes(&self.priv_params);
            })
        })
    }

    /// Decodes incoming security parameters.
    ///
    /// The decoded values can be used to build response or report messages.
    ///
    /// # Errors
    ///
    /// If the message is not properly formed a result with
    /// [MalformedSecurityParams](enum.SecurityError.html#variant.MalformedSecurityParams) error is
    /// returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use snmp_usm::{SecurityParams, Sha1};
    ///
    /// # fn main() -> snmp_usm::SecurityResult<()> {
    /// # let in_security_params = [];
    /// let mut security_params =
    ///    SecurityParams::decode(&in_security_params)?;
    /// security_params.set_username(b"username")
    ///     .set_auth_params_placeholder::<Sha1>();
    /// // A message processing subsystem would set the security parameters of the outgoing message.
    /// // out_msg.set_security_params(&security_params);
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(buf: &[u8]) -> SecurityResult<Self> {
        let result = yasna::parse_ber(buf, |reader| {
            reader.read_sequence(|reader| {
                let engine_id = reader.next().read_bytes()?;
                let engine_boots = reader.next().read_u32()?;
                let engine_time = reader.next().read_u32()?;
                let username = reader.next().read_bytes()?;
                let auth_params = reader.next().read_bytes()?;
                let priv_params = reader.next().read_bytes()?;

                Ok(Self {
                    engine_id,
                    engine_boots,
                    engine_time,
                    username,
                    auth_params,
                    priv_params,
                })
            })
        });

        result.map_err(|_| SecurityError::MalformedSecurityParams)
    }
}
