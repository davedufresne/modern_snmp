//! Main doc.
use anyhow::Result;
use clap::Parser as _;
use msnmp::{self, Params};

fn main() -> Result<()> {
    let args = Params::try_parse()?;
    msnmp::run(args)?;

    Ok(())
}
