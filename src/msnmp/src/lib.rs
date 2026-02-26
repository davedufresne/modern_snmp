mod client;
mod format_var_bind;
mod msg_factory;
mod params;
mod request;
mod session;

use anyhow::Result;
use client::Client;
pub use params::{Command, Params};
use session::{Session, Step};
use snmp_mp::PduType;
use snmp_usm::{
    Aes128PrivKey, AuthKey, DesPrivKey, Digest, LocalizedKey, Md5, PrivKey, Sha1, WithLocalizedKey,
};

const SNMP_PORT_NUM: u32 = 161;

macro_rules! execute_request {
    ($digest:ty, $params:expr) => {{
        if Some(Params::AES128_ENCRYPTION) == $params.privacy_protocol.as_deref() {
            let salt = rand::random();
            execute_request::<
                $digest,
                Aes128PrivKey<$digest>,
                <Aes128PrivKey<$digest> as PrivKey>::Salt,
            >($params, salt)
        } else {
            let salt = rand::random();
            execute_request::<$digest, DesPrivKey<$digest>, <DesPrivKey<$digest> as PrivKey>::Salt>(
                $params, salt,
            )
        }
    }};
}

pub fn run(params: Params) -> Result<()> {
    if Some(Params::SHA1_DIGEST) == params.auth_protocol.as_deref() {
        execute_request!(Sha1, params)
    } else {
        execute_request!(Md5, params)
    }
}

fn execute_request<'a, D, P, S>(params: Params, salt: P::Salt) -> Result<()>
where
    D: Digest + 'a,
    P: PrivKey<Salt = S> + WithLocalizedKey<'a, D>,
    S: Step + Copy,
{
    let host = if params.host.find(':').is_none() {
        format!("{}:{}", params.host, SNMP_PORT_NUM)
    } else {
        params.host
    };

    let mut client = Client::new(host)?;
    let mut session = Session::new(&mut client, params.user.as_bytes())?;

    if let Some(auth_passwd) = params.auth {
        let localized_key = LocalizedKey::<D>::new(auth_passwd.as_bytes(), session.engine_id());
        let auth_key = AuthKey::new(localized_key);
        session.set_auth_key(auth_key);

        if let Some(priv_passwd) = params.privacy {
            let localized_key = LocalizedKey::<D>::new(priv_passwd.as_bytes(), session.engine_id());
            let priv_key = P::with_localized_key(localized_key);
            session.set_priv_key_and_salt(priv_key, salt);
        }
    }

    match params.cmd {
        Command::Get { oids } => {
            request::snmp_get(PduType::GetRequest, oids, &mut client, &mut session)?;
        }
        Command::GetNext { oids } => {
            request::snmp_get(PduType::GetRequest, oids, &mut client, &mut session)?;
        }
        Command::Walk { oid } => {
            request::snmp_walk(oid, &mut client, &mut session)?;
        }
    }

    Ok(())
}
