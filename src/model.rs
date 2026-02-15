///what command line arguments the server accepts
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "FlashProxy")]
#[command(version = "1.0")]
#[command(about = "A high-performance reverse proxy built with Pingora", long_about = None)]
pub struct ProxyArgs {
    /// The port that proxy connects to
    #[arg(short, long, default_value_t = 6188)]
    pub port: u16,

    /// list of servers separated by commas
    #[arg(short, long, required = true)]
    pub upstreams: String,
}
