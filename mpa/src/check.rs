use myna::jpki::KeyType;
use myna::reader::MynaReader;
use serde_json::{Value, json};
use std::io;

/// 項目ごとの判定結果
const SUCCESS: &str = "success";
const FAILURE: &str = "failure";
/// 前提となる項目が失敗したため実施しなかった
const SKIPPED: &str = "skipped";

fn item(name: &str, status: &str, detail: impl Into<String>) -> Value {
    json!({
        "name": name,
        "status": status,
        "detail": detail.into(),
    })
}

/// PIN残り回数の項目。0はブロック状態なので失敗とする。
fn pin_item(name: &str, counter: Result<u8, myna::error::Error>) -> Value {
    match counter {
        Ok(0) => item(name, FAILURE, "ブロックされています"),
        Ok(n) => item(name, SUCCESS, format!("残り{}回", n)),
        Err(e) => item(name, FAILURE, e.to_string()),
    }
}

pub fn check() -> io::Result<()> {
    let config = crate::load_config()?;
    let uuid = config["uuid"]
        .as_str()
        .ok_or_else(|| io::Error::other("uuid not found in config"))?;

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

    let mut checks = Vec::new();
    match reader.connect() {
        Ok(()) => {
            checks.push(item("connect", SUCCESS, ""));
            match reader.jpki_ap() {
                Ok(mut jpki) => {
                    checks.push(item("select_jpki", SUCCESS, ""));
                    checks.push(pin_item(
                        "jpki_auth_pin_counter",
                        jpki.read_pin(&KeyType::Auth),
                    ));
                    checks.push(pin_item(
                        "jpki_sign_pin_counter",
                        jpki.read_pin(&KeyType::Sign),
                    ));
                }
                Err(e) => {
                    checks.push(item("select_jpki", FAILURE, e.to_string()));
                    checks.push(item("jpki_auth_pin_counter", SKIPPED, ""));
                    checks.push(item("jpki_sign_pin_counter", SKIPPED, ""));
                }
            }
        }
        Err(e) => {
            checks.push(item("connect", FAILURE, e.to_string()));
            checks.push(item("select_jpki", SKIPPED, ""));
            checks.push(item("jpki_auth_pin_counter", SKIPPED, ""));
            checks.push(item("jpki_sign_pin_counter", SKIPPED, ""));
        }
    }

    crate::send_message(&json!({
        "mode": "check",
        "result": "0",
        "version": env!("CARGO_PKG_VERSION"),
        "app": "mpa",
        "uuid": uuid,
        "pid": std::process::id(), // そのうち消す
        "check": checks,
    }))
}
