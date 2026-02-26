use crate::{format_var_bind, msg_factory, Client, Session, Step};
use anyhow::{anyhow, Result};
use snmp_mp::{ObjectIdent, PduType, SnmpMsg, VarBind, VarValue};
use snmp_usm::{Digest, PrivKey};
use std::str::FromStr;

const MIB2_BASE_OID: [u64; 6] = [1, 3, 6, 1, 2, 1];

pub fn snmp_get<D, P, S>(
    pdu_type: PduType,
    oids: Vec<String>,
    client: &mut Client,
    session: &mut Session<D, P, S>,
) -> Result<()>
where
    D: Digest,
    P: PrivKey<Salt = S>,
    S: Step + Copy,
{
    let var_binds = strings_to_var_binds(oids.iter());
    if var_binds.is_empty() {
        return Err(anyhow!("invalid OID(s) supplied"));
    }

    let mut get_request = msg_factory::create_request_msg(pdu_type, var_binds, session);

    let response = client.send_request(&mut get_request, session)?;
    if let Some(var_binds) = get_var_binds(&response) {
        for var_bind in var_binds {
            println!("{}", format_var_bind::format_var_bind(var_bind));
        }
    }

    Ok(())
}

pub fn snmp_walk<D, P, S>(
    oid: Option<String>,
    client: &mut Client,
    session: &mut Session<D, P, S>,
) -> Result<()>
where
    D: Digest,
    P: PrivKey<Salt = S>,
    S: Step + Copy,
{
    let mut var_bind = strings_to_var_binds(oid.iter());
    if oid.is_some() && var_bind.is_empty() {
        eprintln!("invalid OID supplied, using default OID\n");
    }

    if var_bind.is_empty() {
        let base_oid = ObjectIdent::from_slice(&MIB2_BASE_OID);
        var_bind = vec![VarBind::new(base_oid)];
    }

    let end_oid = &next_sibling(var_bind[0].name());
    loop {
        let mut get_next_request =
            msg_factory::create_request_msg(PduType::GetNextRequest, var_bind, session);

        let get_next_response = client.send_request(&mut get_next_request, session)?;
        match get_first_var_bind(&get_next_response) {
            Some(var) => {
                if var.name() >= end_oid || var.value() == &VarValue::EndOfMibView {
                    return Ok(());
                }

                println!("{}", format_var_bind::format_var_bind(var));
                var_bind = vec![VarBind::new(var.name().clone())];
            }
            None => return Ok(()),
        }
    }
}

fn strings_to_var_binds<'a, I>(strings: I) -> Vec<VarBind>
where
    I: Iterator<Item = &'a String>,
{
    strings
        .map(|oid_str| ObjectIdent::from_str(oid_str))
        .filter_map(Result::ok)
        .map(VarBind::new)
        .collect()
}

fn get_var_binds(msg: &SnmpMsg) -> Option<&[VarBind]> {
    Some(msg.scoped_pdu_data.plaintext()?.var_binds())
}

fn get_first_var_bind(msg: &SnmpMsg) -> Option<&VarBind> {
    get_var_binds(msg)?.first()
}

fn next_sibling(oid: &ObjectIdent) -> ObjectIdent {
    let mut components = oid.components().to_vec();
    let len = components.len();
    components[len - 1] = components[len - 1].wrapping_add(1);

    ObjectIdent::new(components)
}
