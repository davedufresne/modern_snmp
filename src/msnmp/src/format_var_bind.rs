use snmp_mp::{VarBind, VarValue};

const SECONDS_IN_MINUTE: u32 = 60;
const SECONDS_IN_HOUR: u32 = 60 * SECONDS_IN_MINUTE;
const SECONDS_IN_DAY: u32 = SECONDS_IN_HOUR * 24;

pub fn format_var_bind(var_bind: &VarBind) -> String {
    format!(
        "{} = {}",
        var_bind.name(),
        format_var_value(var_bind.value())
    )
}

fn format_var_value(var_value: &VarValue) -> String {
    match var_value {
        VarValue::Int(i) => format!("INTEGER: {}", i),
        VarValue::String(s) => format!("STRING: {:?}", String::from_utf8_lossy(s)),
        VarValue::ObjectId(oid) => format!("OID: {}", oid),
        VarValue::IpAddress(ip) => format!("IP ADDRESS: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        VarValue::Counter(c) => format!("COUNTER: {}", c),
        VarValue::UnsignedInt(ui) => format!("UNSIGNED INTEGER: {}", ui),
        VarValue::TimeTicks(time_ticks) => {
            let hundredth = time_ticks % 100;
            let remaining_seconds = time_ticks / 100;
            let days = remaining_seconds / SECONDS_IN_DAY;
            let remaining_seconds = remaining_seconds % SECONDS_IN_DAY;

            let hours = remaining_seconds / SECONDS_IN_HOUR;
            let remaining_seconds = remaining_seconds % SECONDS_IN_HOUR;

            let minutes = remaining_seconds / SECONDS_IN_MINUTE;
            let seconds = remaining_seconds % SECONDS_IN_MINUTE;

            format!(
                "TIME TICKS: ({}) {} day(s) {}:{:0>2}:{:0>2}.{:0>2}",
                time_ticks, days, hours, minutes, seconds, hundredth
            )
        }
        VarValue::Opaque(o) => format!("OPAQUE: {:X?}", o),
        VarValue::BigCounter(bc) => format!("BIG COUNTER: {}", bc),
        VarValue::Unspecified => "Unspecified".to_string(),
        VarValue::NoSuchObject => "No such object".to_string(),
        VarValue::NoSuchInstance => "No such instance".to_string(),
        VarValue::EndOfMibView => "End of MIB view".to_string(),
    }
}
