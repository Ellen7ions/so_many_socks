use std::str::FromStr;
use std::env;
use std::env::Args;
use std::net::{IpAddr, Ipv4Addr};
use crate::ParseErr::{MissArgsErr, ParseAddrErr, ParsePortErr};

mod server;

use server::SocksServer;

const DEFAULT_IP: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 23333;

#[derive(Debug)]
struct ParseArgs {
    ip: IpAddr,
    port: u16,
}

impl ParseArgs {
    fn get_default_args() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::from_str(DEFAULT_IP).unwrap()),
            port: DEFAULT_PORT,
        }
    }
}

#[derive(Debug)]
enum ParseErr {
    ParseAddrErr,
    ParsePortErr,
    MissArgsErr(String),
    UnknownArgs(String),
}


fn parse_args(mut args: Args) -> Result<ParseArgs, ParseErr> {
    let mut parse_args = ParseArgs::get_default_args();
    args.next();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-a" => {
                if let Some(val) = args.next() {
                    if let Ok(ip) = Ipv4Addr::from_str(val.as_str()) {
                        parse_args.ip = IpAddr::V4(ip);
                    } else {
                        return Err(ParseAddrErr);
                    }
                } else { return Err(MissArgsErr(arg)); };
            }
            "-p" => {
                if let Some(val) = args.next() {
                    if let Ok(port) = val.parse() {
                        parse_args.port = port;
                    } else {
                        return Err(ParsePortErr);
                    }
                } else { return Err(MissArgsErr(arg)); };
            }
            _ => return Err(ParseErr::UnknownArgs(arg))
        }
    }
    return Ok(parse_args);
}

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    println!("Cargo? Run!");
    let args = parse_args(env::args());
    println!("{:?}", args.unwrap());
    SocksServer::startup(args.unwrap()).await.unwrap();
    Ok(())
}
