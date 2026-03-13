use std::io;
use serde_json::json;

pub fn check() -> io::Result<()> {
    let response = json!({
        "mode": "check",
        "result": "0",
        "version": env!("CARGO_PKG_VERSION"),
        "app": "mpa",
        "pid": std::process::id(),
    });
    crate::send_message(&response)
}
