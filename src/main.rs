mod apdu;
mod jpki;
mod pin;
mod pkcs7;
mod prompt;
mod reader;
mod test;
mod text;
mod utils;
mod visual;
use clap::{Args, Parser, Subcommand};
use jpki::JPKI;
use pin::Pin;
use text::TextSubcommand;
use visual::VisualSubcommand;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
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
                jpki::main(self, command);
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
    /// JPKI
    #[command(subcommand)]
    JPKI(JPKI),
    /// Pin operation
    #[command(subcommand)]
    Pin(Pin),
}

#[derive(Args)]
struct TestArgs {
    name: Option<String>,
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
