use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct Params {
    #[structopt(short, long, required = true)]
    pub user: String,
    #[structopt(short, long, required = true)]
    pub host: String,
    #[structopt(short, long)]
    pub auth: Option<String>,
    #[structopt(short = "A", long, possible_values = &[Self::MD5_DIGEST, Self::SHA1_DIGEST])]
    pub auth_protocol: Option<String>,
    #[structopt(short, long)]
    pub privacy: Option<String>,
    #[structopt(short = "P", long, possible_values = &[Self::DES_ENCRYPTION, Self::AES128_ENCRYPTION])]
    pub privacy_protocol: Option<String>,
    #[structopt(subcommand)]
    pub cmd: Command,
}

impl Params {
    pub const MD5_DIGEST: &'static str = "MD5";
    pub const SHA1_DIGEST: &'static str = "SHA1";
    pub const DES_ENCRYPTION: &'static str = "DES";
    pub const AES128_ENCRYPTION: &'static str = "AES128";
}

#[derive(StructOpt, Debug)]
pub enum Command {
    #[structopt(about = "Performs an SNMP GET operation")]
    Get {
        #[structopt(
            name = "OID",
            help = "One or more object identifiers separated by spaces",
            required = true
        )]
        oids: Vec<String>,
    },
    #[structopt(about = "Performs an SNMP GET NEXT operation")]
    GetNext {
        #[structopt(
            name = "OID",
            help = "One or more object identifiers separated by spaces",
            required = true
        )]
        oids: Vec<String>,
    },
    #[structopt(about = "Retrieves a subtree of management values")]
    Walk {
        #[structopt(name = "OID", help = "Optional object identifier")]
        oid: Option<String>,
    },
}
