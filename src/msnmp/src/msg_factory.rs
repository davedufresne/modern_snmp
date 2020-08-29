use crate::Session;
use snmp_mp::{self, PduType, SnmpMsg, VarBind};

pub fn create_reportable_msg<D, P, S>(session: &mut Session<D, P, S>) -> SnmpMsg {
    let mut reportable_msg = SnmpMsg::new(session.msg_id());
    reportable_msg.set_reportable_flag();

    if let Some(scoped_pdu) = reportable_msg.scoped_pdu_data.plaintext_mut() {
        scoped_pdu
            .set_request_id(session.request_id())
            .set_engine_id(session.engine_id());
    }

    reportable_msg
}

pub fn create_request_msg<I, D, P, S>(
    pdu_type: PduType,
    var_binds_iter: I,
    session: &mut Session<D, P, S>,
) -> SnmpMsg
where
    I: IntoIterator<Item = VarBind>,
{
    let mut get_request = create_reportable_msg(session);
    if let Some(scoped_pdu) = get_request.scoped_pdu_data.plaintext_mut() {
        scoped_pdu
            .set_pdu_type(pdu_type)
            .set_var_binds(var_binds_iter);
    }

    get_request
}
