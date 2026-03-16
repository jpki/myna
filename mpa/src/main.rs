use log::{LevelFilter, info};
use myna::jpki::{CertType, KeyType};
use myna::reader::MynaReader;
use myna::utils;
use serde::Serialize;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};

mod check;

#[derive(Serialize)]
struct SuccessResponse {
    mode: String,
    result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uuid: Option<&'static str>,
    signature: String,
    certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    combination_code: Option<&'static str>,
}

#[derive(Serialize)]
struct ErrorResponse {
    result: &'static str,
}

fn setup_logging() -> Result<(), fern::InitError> {
    let mut dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(LevelFilter::Info);

    #[cfg(debug_assertions)]
    {
        dispatch = dispatch.chain(std::io::stderr());
    }

    if let Some(log_path) = std::env::var_os("MPA_LOG") {
        let log_file = OpenOptions::new().create(true).append(true).open(log_path)?;
        dispatch = dispatch.chain(log_file);
    } else if !cfg!(debug_assertions) {
        return Ok(());
    }

    dispatch.apply()?;
    Ok(())
}

fn recv_message() -> io::Result<Value> {
    let mut len_buf = [0u8; 4];
    io::stdin().read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; len];
    io::stdin().read_exact(&mut msg_buf)?;

    let raw =
        String::from_utf8(msg_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let val: Value =
        serde_json::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // ログ出力のためPINを削除
    let mut masked = val.clone();
    if let Some(obj) = masked.as_object_mut() {
        obj.remove("pin");
    }
    let masked_raw = serde_json::to_string(&masked)
        .unwrap_or_else(|_| raw.trim_end_matches(['\r', '\n']).to_string());
    info!("recv: {}", masked_raw);

    Ok(val)
}

pub(crate) fn send_message<T: Serialize>(msg: &T) -> io::Result<()> {
    let data = serde_json::to_vec(msg)?;

    if let Ok(raw) = String::from_utf8(data.clone()) {
        info!("send: {}", raw);
    }

    let len = (data.len() as u32).to_le_bytes();
    let mut stdout = io::stdout().lock();
    stdout.write_all(&len)?;
    stdout.write_all(&data)?;
    stdout.flush()
}

fn send_error_response(message: &str) -> io::Result<()> {
    log::error!("{}", message);
    send_message(&ErrorResponse { result: "1" })
}

fn auth_pin(msg: &Value) -> Option<String> {
    let env_pin = std::env::var("MPA_PIN").ok();
    msg.get("pin")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| env_pin.clone())
}

fn auth(msg: &Value) -> io::Result<()> {
    let service_id = msg.get("service_id").and_then(|v| v.as_str());

    if service_id != Some("01") {
        return send_error_response("Unsupported service_id");
    }

    let digest_b64 = match msg.get("digest").and_then(|v| v.as_str()) {
        Some(digest) => digest,
        None => return send_error_response("digest is required"),
    };

    let pin = auth_pin(msg);

    let mut reader = match MynaReader::new().and_then(|mut r| {
        r.timeout = Some(std::time::Duration::from_secs(5));
        r.connect()?;
        Ok(r)
    }) {
        Ok(r) => r,
        Err(e) => return send_error_response(&format!("failed to connect: {}", e)),
    };
    let mut jpki = match reader.jpki_ap() {
        Ok(j) => j,
        Err(e) => return send_error_response(&format!("failed to select JPKI AP: {}", e)),
    };

    let digest = match utils::base64_decode(digest_b64) {
        Ok(d) => d,
        Err(e) => return send_error_response(&format!("failed to decode digest: {}", e)),
    };
    let signature = match jpki.pkey_sign(&KeyType::Auth, &pin, &digest) {
        Ok(sig) => utils::base64_encode(&sig),
        Err(e) => return send_error_response(&format!("failed to sign digest: {}", e)),
    };

    let certificate = match jpki.cert_read(&CertType::Auth, &None, &pin) {
        Ok(cert) => match cert.to_der() {
            Ok(der) => utils::base64_encode_nopad(&der),
            Err(e) => return send_error_response(&format!("failed to encode certificate: {}", e)),
        },
        Err(e) => return send_error_response(&format!("failed to load certificate: {}", e)),
    };

    let response = SuccessResponse {
        mode: "01".to_string(),
        result: "0".to_string(),
        uuid: None,
        signature,
        certificate,
        combination_code: None,
    };
    send_message(&response)
}

fn main() -> io::Result<()> {
    eprintln!("Host Application started");
    setup_logging().map_err(io::Error::other)?;
    loop {
        let msg = match recv_message() {
            Ok(msg) => msg,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        let mode = msg.get("mode").and_then(|v| v.as_str());

        match mode {
            Some("check") => check::check()?,
            Some("01") => auth(&msg)?,
            Some("05") => {
                log::info!("received close request");
                break;
            }
            _ => send_error_response(&format!("Unsupported mode {:?}", mode))?,
        }
    }
    Ok(())
}
