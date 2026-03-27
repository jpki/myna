mod check;
mod cli;

use clap::Parser;

fn main() {
    let app = cli::App::parse();
    init_logger(app.log_level()).expect("failed to initialize logger");
    if let Err(e) = app.run() {
        eprintln!("Error: {}", e);
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
