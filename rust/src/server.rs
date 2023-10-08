use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use crate::ParseArgs;

use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};

use crate::server::SocksError::{NoSupportMethod, SocksParseError, NoSupportAddrType};

pub struct SocksServer;

enum SocksState {
    Connect,
    Authed,
}

#[derive(Clone, Copy)]
enum SocksConnectMethod {
    NoAuth = 0,
    GSSAPI = 1,
    UserPwd = 2,
}

#[derive(Debug)]
enum SocksError {
    SocksParseError,
    NoSupportMethod,
    NoSupportAddrType,
    SocketIOError,
}

impl Display for SocksError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for SocksError {}

impl From<io::Error> for SocksError {
    fn from(_value: io::Error) -> Self {
        SocksError::SocketIOError
    }
}

fn parse_cli_req(buf: &[u8], n: usize) -> Result<SocksConnectMethod, SocksError> {
    if n < 3 || buf[0] != 5 || buf[1] == 0 {
        return Err(SocksParseError);
    }
    for i in 0..buf[1] {
        match buf[2 + i as usize] {
            x if x == (SocksConnectMethod::NoAuth as u8) => { return Ok(SocksConnectMethod::NoAuth); }
            x if x == (SocksConnectMethod::GSSAPI as u8) || x == (SocksConnectMethod::UserPwd as u8) => {}
            _ => {}
        }
    }
    Err(NoSupportMethod)
}

async fn parse_cli_svc_req(buf: &[u8], n: usize) -> Result<TcpStream, SocksError> {
    if n < 5 || buf[0] != 5 || buf[2] != 0 { return Err(SocksParseError); }

    let ip = match buf[3] {
        1 => {
            Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])
        }
        _ => { return Err(NoSupportAddrType); }
    };
    let port: u16 = (buf[8] as u16) << 8 | buf[9] as u16;
    let req_addr = SocketAddr::new(IpAddr::V4(ip), port);
    let rmt_stream = TcpStream::connect(req_addr).await.unwrap();
    Ok(rmt_stream)
}

async fn forward(mut cli_stream: TcpStream, mut rmt_stream: TcpStream) -> Result<(), SocksError> {
    let mut buf1: [u8; 1024] = [0; 1024];
    let mut buf2: [u8; 1024] = [0; 1024];

    // let mut cli_stream = tokio::net::TcpStream::from_std(cli_stream).unwrap();
    // let mut rmt_stream = tokio::net::TcpStream::from_std(rmt_stream).unwrap();

    loop {
        tokio::select! {
			a = cli_stream.read(&mut buf1) => {
				let len = match a {
					Err(_) => {
						break;
					}
					Ok(p) => p
				};
				match rmt_stream.write_all(&buf1[..len]).await {
					Err(_) => {
                        println!("rmt write all err");
						break;
					}
					Ok(p) => p
				};

				if len == 0 {
					break;
				}
			},
			b = rmt_stream.read(&mut buf2) =>  {
				let len = match b{
					Err(_) => {
						break;
					}
					Ok(p) => p
				};
				match cli_stream.write_all(&buf2[..len]).await {
					Err(_) => {
                        println!("cli read all err");
						break;
					}
					Ok(p) => p
				};
				if len == 0 {
					break;
				}
			},
		}
    }

    Ok(())
}

async fn socks_handler(mut stream: TcpStream, mut state: SocksState) -> Result<(), SocksError> {
    let mut buf = [0; 1024];
    while let Ok(n) = stream.read(&mut buf).await {
        println!("recv {} bytes", n);
        if n == 0 { break; }
        match state {
            SocksState::Connect => {
                let mtd = parse_cli_req(&buf, n)?;
                println!("recv mtd {}", mtd as u8);
                let resp: [u8; 2] = [5, mtd as u8];
                stream.write_all(&resp).await?;
                state = SocksState::Authed;
            }
            SocksState::Authed => {
                let rmt_stream = parse_cli_svc_req(&buf, n).await?;
                let resp: [u8; 10] = [5, 0, 0, 1 /*AT_IPV4*/, 0, 0, 0, 0, 0, 0];
                stream.write_all(&resp).await?;
                forward(stream, rmt_stream).await?;
                break;
            }
        }
    }

    Ok(())
}

impl SocksServer {
    pub async fn startup(args: ParseArgs) -> io::Result<()> {
        let listener = TcpListener::bind(SocketAddr::new(args.ip, args.port)).await?;

        loop {
            let (stream, addr) = listener.accept().await?;
            println!("A client from {}:{} connect to our socks server.", addr.ip(), addr.port());

            tokio::spawn(socks_handler(stream, SocksState::Connect));
        }
    }
}
