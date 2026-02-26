use clap::Parser;

#[derive(Parser, Debug)]
#[clap()]
pub struct Params {
    #[clap(short, long, required = true)]
    pub user: String,
    #[clap(short, long, required = true)]
    pub host: String,
    #[clap(short, long)]
    pub auth: Option<String>,
    #[clap(short = 'A', long, value_parser = clap::builder::PossibleValuesParser::new([Self::MD5_DIGEST, Self::SHA1_DIGEST]))]
    pub auth_protocol: Option<String>,
    #[clap(short, long)]
    pub privacy: Option<String>,
    #[clap(short = 'P', long, value_parser = clap::builder::PossibleValuesParser::new([Self::DES_ENCRYPTION, Self::AES128_ENCRYPTION]))]
    pub privacy_protocol: Option<String>,
    #[clap(subcommand)]
    pub cmd: Command,
}

impl Params {
    pub const MD5_DIGEST: &'static str = "MD5";
    pub const SHA1_DIGEST: &'static str = "SHA1";
    pub const DES_ENCRYPTION: &'static str = "DES";
    pub const AES128_ENCRYPTION: &'static str = "AES128";
}

#[derive(Parser, Debug)]
pub enum Command {
    #[clap(about = "Performs an SNMP GET operation")]
    Get {
        #[clap(
            name = "OID",
            help = "One or more object identifiers separated by spaces",
            required = true
        )]
        oids: Vec<String>,
    },
    #[clap(about = "Performs an SNMP GET NEXT operation")]
    GetNext {
        #[clap(
            name = "OID",
            help = "One or more object identifiers separated by spaces",
            required = true
        )]
        oids: Vec<String>,
    },
    #[clap(about = "Retrieves a subtree of management values")]
    Walk {
        #[clap(name = "OID", help = "Optional object identifier")]
        oid: Option<String>,
    },
}
