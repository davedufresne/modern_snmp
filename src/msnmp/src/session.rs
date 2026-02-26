use crate::client::Client;
use crate::msg_factory;
use rand::prelude::*;
use rand::rng;
use snmp_mp::{ScopedPdu, SnmpMsg};
use snmp_usm::{AuthKey, Digest, PrivKey, SecurityParams};
use std::io::Result;
use std::time::Instant;

// Trait implemented by types representing a cryptographic salt. It allows those 'salt' types to be
// used generically.
pub trait Step {
    fn next(&self) -> Self;
}

impl Step for u32 {
    fn next(&self) -> Self {
        self.wrapping_add(1)
    }
}

impl Step for u64 {
    fn next(&self) -> Self {
        self.wrapping_add(1)
    }
}

// Contains the information of a session with an SNMP engine.
//
// Before requests can be sent to an SNMP engine a discovery process has to take place. If
// authentication is requested time synchronization has also to be performed. `Session`
// contains the information gathered from these processes.
#[derive(Debug, Clone)]
pub struct Session<'a, D, P, S> {
    username: Vec<u8>,
    engine_id: Vec<u8>,
    engine_boots: u32,
    engine_time: u32,
    msg_id: u32,
    request_id: i32,
    sync_time: Instant,
    auth_key: Option<AuthKey<'a, D>>,
    priv_key: Option<(P, S)>,
}

impl<'a, D, P, S> Session<'a, D, P, S> {
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    pub fn set_username(&mut self, username: &[u8]) -> &mut Self {
        self.username.clear();
        self.username.extend_from_slice(username);
        self
    }

    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    pub fn set_engine_id(&mut self, engine_id: &[u8]) -> &mut Self {
        self.engine_id.clear();
        self.engine_id.extend_from_slice(engine_id);
        self
    }

    pub fn engine_boots(&self) -> u32 {
        self.engine_boots
    }

    pub fn set_engine_boots(&mut self, engine_boots: u32) -> &mut Self {
        self.engine_boots = engine_boots;
        self
    }

    pub fn engine_time(&self) -> u32 {
        self.engine_time + self.sync_time.elapsed().as_secs() as u32
    }

    pub fn set_engine_time(&mut self, engine_time: u32) -> &mut Self {
        self.engine_time = engine_time;
        self.sync_time = Instant::now();
        self
    }

    pub fn msg_id(&mut self) -> u32 {
        let msg_id = self.msg_id;
        let next_id = self.msg_id.wrapping_add(1);
        self.msg_id = if next_id > SnmpMsg::MSG_ID_MAX {
            SnmpMsg::MSG_ID_MIN
        } else {
            next_id
        };

        msg_id
    }

    pub fn request_id(&mut self) -> i32 {
        let request_id = self.request_id;
        let next_id = self.request_id.wrapping_add(1);
        self.request_id = if next_id > ScopedPdu::REQUEST_ID_MAX {
            ScopedPdu::REQUEST_ID_MIN
        } else {
            next_id
        };

        request_id
    }

    pub fn auth_key(&self) -> &Option<AuthKey<'_, D>> {
        &self.auth_key
    }

    pub fn set_auth_key(&mut self, auth_key: AuthKey<'a, D>) -> &mut Self {
        self.auth_key = Some(auth_key);
        self
    }

    pub fn priv_key(&self) -> Option<&P> {
        if let Some((ref priv_key, _)) = self.priv_key {
            return Some(priv_key);
        }

        None
    }
}

impl<'a, D, P, S> Session<'a, D, P, S>
where
    D: Digest,
    P: PrivKey<Salt = S>,
    S: Step + Copy,
{
    pub fn new(client: &mut Client, username: &[u8]) -> Result<Self> {
        let mut rng = rng();

        let mut session = Self {
            username: Default::default(),
            engine_id: Default::default(),
            engine_boots: Default::default(),
            engine_time: Default::default(),
            msg_id: rng.random_range(SnmpMsg::MSG_ID_MIN..SnmpMsg::MSG_ID_MAX),
            request_id: rng.random_range(ScopedPdu::REQUEST_ID_MIN..ScopedPdu::REQUEST_ID_MAX),
            sync_time: Instant::now(),
            auth_key: None,
            priv_key: None,
        };

        let mut discovery_msg = msg_factory::create_reportable_msg(&mut session);
        let discovery_response = client.send_request(&mut discovery_msg, &mut session)?;

        let security_params = SecurityParams::decode(discovery_response.security_params())?;
        session
            .set_username(username)
            .set_engine_id(security_params.engine_id())
            .set_engine_boots(security_params.engine_boots())
            .set_engine_time(security_params.engine_time());

        Ok(session)
    }

    pub fn priv_key_and_salt(&mut self) -> Option<(&P, P::Salt)> {
        if let Some((ref priv_key, ref mut salt)) = self.priv_key {
            let prev_salt = *salt;
            *salt = prev_salt.next();

            return Some((priv_key, prev_salt));
        }

        None
    }

    pub fn set_priv_key_and_salt(&mut self, priv_key: P, salt: P::Salt) -> &mut Self {
        self.priv_key = Some((priv_key, salt));
        self
    }
}
