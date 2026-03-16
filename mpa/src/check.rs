use myna::reader::MynaReader;
use serde_json::json;
use std::io;

pub fn check() -> io::Result<()> {
    let mut reader = match MynaReader::new() {
        Ok(r) => r,
        Err(e) => {
            return crate::send_message(&json!({
                "mode": "check",
                "result": "1",
                "error": format!("{}", e),
            }));
        }
    };
    reader.timeout = Some(std::time::Duration::from_secs(5));

    let connect = match reader.connect() {
        Ok(()) => "OK".to_string(),
        Err(e) => format!("{}", e),
    };

    let select_jpki = if connect == "OK" {
        match reader.jpki_ap() {
            Ok(_) => "OK".to_string(),
            Err(e) => format!("{}", e),
        }
    } else {
        "".to_string()
    };

    crate::send_message(&json!({
        "mode": "check",
        "result": "0",
        "version": env!("CARGO_PKG_VERSION"),
        "app": "mpa",
        "pid": std::process::id(), // そのうち消す
        "check": [
            ["pid", std::process::id()],
            ["connect", connect],
            ["select_jpki", select_jpki],
        ],
    }))
}
