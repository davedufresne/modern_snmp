//! Main doc.
use exitfailure::ExitFailure;
use msnmp::{self, Params};
use structopt::StructOpt;

fn main() -> Result<(), ExitFailure> {
    let args = Params::from_args();
    msnmp::run(args)?;

    Ok(())
}
