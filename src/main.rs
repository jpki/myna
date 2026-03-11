mod pin;
mod test;
mod text;
mod visual;
use clap::{Args, Parser, Subcommand};
use myna::jpki::JPKI;
use myna::unknown::UnknownSubcommand;
use pin::Pin;
use text::TextSubcommand;
use visual::VisualSubcommand;

#[derive(Parser)]
#[command(author, version, long_version = long_version(), about, long_about = None)]
#[command(propagate_version = true)]
pub struct App {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long)]
    debug: bool,
}

impl App {
    pub fn run(&self) {
        match &self.command {
            Commands::Pin(command) => {
                pin::main(self, command);
            }
            Commands::JPKI(command) => {
                myna::jpki::main(command);
            }
            Commands::Text(command) => {
                text::main(self, command);
            }
            Commands::Visual(command) => {
                visual::main(self, command);
            }
            Commands::Test(_command) => {
                test::test(self);
            }
            Commands::Unknown(command) => {
                myna::unknown::main(command);
            }
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// 券面入力補助AP
    #[command(subcommand)]
    Text(TextSubcommand),
    /// 券面確認AP
    #[command(subcommand)]
    Visual(VisualSubcommand),
    /// Test card reader
    Test(TestArgs),
    /// 公的個人認証
    #[command(subcommand)]
    JPKI(JPKI),
    /// Pin operation
    #[command(subcommand)]
    Pin(Pin),
    /// 謎のAP
    #[command(subcommand)]
    Unknown(UnknownSubcommand),
}

#[derive(Args)]
struct TestArgs {
    name: Option<String>,
}

fn long_version() -> &'static str {
    use std::sync::OnceLock;
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        format!(
            "{}\n{}",
            env!("CARGO_PKG_VERSION"),
            openssl::version::version()
        )
    })
}

fn main() {
    let app = App::parse();
    let mut builder = env_logger::Builder::new();
    builder.format_timestamp(None).format_target(false);
    if app.debug {
        builder.filter_level(log::LevelFilter::Debug);
    }
    builder.init();
    app.run();
}
