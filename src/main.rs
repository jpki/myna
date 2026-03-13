mod pin;
mod check;
mod text;
mod visual;
use clap::{ArgAction, Args, Parser, Subcommand};
use myna::jpki::JPKI;
use myna::unknown::UnknownSubcommand;
use pin::Pin;
use text::TextSubcommand;
use visual::VisualSubcommand;

#[derive(Parser)]
#[command(author, version = version(), about, long_about = None)]
#[command(propagate_version = true)]
pub struct App {
    #[command(subcommand)]
    command: Commands,
    #[arg(short = 'v', action = ArgAction::Count, global = true)]
    verbose: u8,
    #[arg(short, long)]
    debug: bool,
}

impl App {
    pub fn run(&self) {
        match &self.command {
            Commands::Pin(command) => pin::main(self, command),
            Commands::JPKI(command) => myna::jpki::main(command),
            Commands::Text(command) => text::main(self, command),
            Commands::Visual(command) => visual::main(self, command),
            Commands::Check(_command) => check::main(self),
            Commands::Unknown(command) => myna::unknown::main(command),
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// 動作診断
    Check(CheckArgs),
    /// 券面入力補助AP
    #[command(subcommand)]
    Text(TextSubcommand),
    /// 券面確認AP
    #[command(subcommand)]
    Visual(VisualSubcommand),
    /// 公的個人認証
    #[command(subcommand)]
    #[allow(clippy::upper_case_acronyms)]
    JPKI(JPKI),
    /// Pin operation
    #[command(subcommand)]
    Pin(Pin),
    /// 謎のAP
    #[command(subcommand)]
    Unknown(UnknownSubcommand),
}

#[derive(Args)]
struct CheckArgs {
    name: Option<String>,
}

fn version() -> &'static str {
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
    init_logger(app.log_level()).expect("failed to initialize logger");
    app.run();
}

impl App {
    fn log_level(&self) -> log::LevelFilter {
        if self.verbose >= 3 {
            log::LevelFilter::Trace
        } else if self.debug || self.verbose >= 2 {
            log::LevelFilter::Debug
        } else if self.verbose >= 1 {
            log::LevelFilter::Info
        } else {
            log::LevelFilter::Warn
        }
    }
}

fn init_logger(level: log::LevelFilter) -> std::result::Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| out.finish(format_args!("[{}] {}", record.level(), message)))
        .level(level)
        .chain(std::io::stderr())
        .apply()?;
    Ok(())
}
