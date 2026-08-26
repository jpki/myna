use der::Encode;
use log::{LevelFilter, info};
use myna::jpki::{CertType, KeyType};
use myna::reader::MynaReader;
use myna::utils;
use serde::Serialize;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};

mod check;

/// Native Messagingで受け付けるメッセージの最大長
const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

/// panicの内容をログにも残す。既定のフックはstderrにしか出力しない。
fn setup_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("{}", info);
        default_hook(info);
    }));
}

#[derive(Serialize)]
struct AuthSuccessResponse {
    mode: String,
    result: String,
    uuid: String,
    signature: String,
    certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    combination_code: Option<String>,
}

#[derive(Serialize)]
struct SignSuccessResponse {
    mode: String,
    result: String,
    uuid: String,
    signature: Vec<String>,
    certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    combination_code: Option<String>,
}

#[derive(Serialize)]
struct TextSuccessResponse {
    mode: String,
    result: String,
    uuid: String,
    name: String,
    sex: String,
    address: String,
    birthday: String,
    combination_code: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    result: String,
    message: String,
}

fn generate_combination_code(manufacture_number: &str, uuid_hex: &str) -> io::Result<String> {
    use sha2::{Digest, Sha256};

    let salt = myna::utils::hex_decode("2e71f6620bc654ced494e5ec34fe03c8")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let uuid_bytes = myna::utils::hex_decode(uuid_hex).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid uuid in config.json (must be hex): {}", e),
        )
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&salt);
    hasher.update(manufacture_number.as_bytes());
    hasher.update(&uuid_bytes);
    Ok(myna::utils::hex_encode(&hasher.finalize()))
}

pub(crate) fn load_config() -> io::Result<Value> {
    let home = std::env::var("HOME").map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;
    let path = std::path::Path::new(&home).join(".config/mpa/config.json");
    let content = std::fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {}", path.display(), e)))?;
    serde_json::from_str(&content).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {}", path.display(), e),
        )
    })
}

/// MPA_LOG_LEVELでログレベルを指定する(既定はinfo)
fn log_level() -> LevelFilter {
    match std::env::var("MPA_LOG_LEVEL")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
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
        .level(log_level());

    #[cfg(debug_assertions)]
    {
        dispatch = dispatch.chain(std::io::stderr());
    }

    if let Some(log_path) = std::env::var_os("MPA_LOG") {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        dispatch = dispatch.chain(log_file);
    } else if !cfg!(debug_assertions) {
        return Ok(());
    }

    dispatch.apply()?;
    Ok(())
}

/// stdinからメッセージを1件受信する。
/// ブラウザーがstdinを閉じた場合(正常終了)はOk(None)を返す。
fn recv_message() -> io::Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    match io::stdin().read_exact(&mut len_buf) {
        Ok(()) => {}
        // 長さの読み込み開始時点でのEOFはブラウザーによる正常なクローズ
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::other(format!(
            "message too large: {} bytes",
            len
        )));
    }

    let mut msg_buf = vec![0u8; len];
    io::stdin().read_exact(&mut msg_buf)?;

    let raw = String::from_utf8(msg_buf).map_err(io::Error::other)?;
    let val: Value = serde_json::from_str(&raw).map_err(io::Error::other)?;

    // ログ出力のためPINを削除
    let mut masked = val.clone();
    if let Some(obj) = masked.as_object_mut() {
        obj.remove("pin");
    }
    let masked_raw = serde_json::to_string(&masked)
        .unwrap_or_else(|_| raw.trim_end_matches(['\r', '\n']).to_string());
    info!("recv: {} ({} bytes)", masked_raw, len);

    Ok(Some(val))
}

pub(crate) fn send_message<T: Serialize>(msg: &T) -> io::Result<()> {
    let data = serde_json::to_vec(msg)?;

    let mut stdout = io::stdout().lock();
    stdout.write_all(&(data.len() as u32).to_le_bytes())?;
    stdout.write_all(&data)?;
    stdout.flush()?;

    // 書き込みとflushが成功した後に記録する
    info!(
        "send: {} ({} bytes)",
        String::from_utf8_lossy(&data),
        data.len()
    );
    Ok(())
}

fn send_error(message: String) -> io::Result<()> {
    log::error!("{}", message);
    send_message(&ErrorResponse {
        result: "1".to_string(),
        message,
    })
}

fn auth_pin(msg: &Value) -> Option<String> {
    let env_pin = std::env::var("MPA_PIN").ok();
    msg.get("pin")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| env_pin.clone())
}

fn auth(msg: &Value) -> io::Result<()> {
    let config = load_config()?;
    let uuid = config["uuid"]
        .as_str()
        .ok_or_else(|| io::Error::other("uuid not found in config"))?;

    let service_id = msg.get("service_id").and_then(|v| v.as_str());

    if service_id != Some("01") {
        return Err(io::Error::other("Unsupported service_id"));
    }

    let digest_b64 = msg
        .get("digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::other("digest is required"))?;

    let pin = auth_pin(msg);

    let mut reader = MynaReader::new()
        .and_then(|mut r| {
            r.timeout = Some(std::time::Duration::from_secs(5));
            r.connect()?;
            Ok(r)
        })
        .map_err(|e| io::Error::other(format!("failed to connect: {}", e)))?;
    let mut jpki = reader
        .jpki_ap()
        .map_err(|e| io::Error::other(format!("failed to select JPKI AP: {}", e)))?;

    let digest = utils::base64_decode(digest_b64)
        .map_err(|e| io::Error::other(format!("failed to decode digest: {}", e)))?;
    jpki.verify(&KeyType::Auth, pin.as_deref().unwrap_or(""))
        .map_err(|e| io::Error::other(e.to_string()))?;
    let signature = jpki
        .pkey_sign(&KeyType::Auth, &digest)
        .map(|sig| utils::base64_encode(&sig))
        .map_err(|e| io::Error::other(format!("failed to sign digest: {}", e)))?;

    let cert = jpki
        .cert_read(&CertType::Auth)
        .map_err(|e| io::Error::other(format!("failed to load certificate: {}", e)))?;
    let certificate = cert
        .to_der()
        .map(|der| utils::base64_encode_nopad(der.as_slice()))
        .map_err(|e| io::Error::other(format!("failed to encode certificate: {}", e)))?;

    let manufacture_number = reader
        .unknown_ap()
        .and_then(|mut u| u.read_manufacture())
        .map_err(|e| io::Error::other(format!("failed to read manufacture number: {}", e)))?;
    let combination_code = generate_combination_code(&manufacture_number, uuid)?;

    let response = AuthSuccessResponse {
        mode: "01".to_string(),
        result: "0".to_string(),
        uuid: uuid.to_string(),
        signature,
        certificate,
        combination_code: Some(combination_code),
    };
    send_message(&response)
}

fn sign(msg: &Value) -> io::Result<()> {
    let config = load_config()?;
    let uuid = config["uuid"]
        .as_str()
        .ok_or_else(|| io::Error::other("uuid not found in config"))?;

    let service_id = msg.get("service_id").and_then(|v| v.as_str());

    if service_id != Some("01") {
        return Err(io::Error::other("Unsupported service_id"));
    }

    let digests_b64: Vec<&str> = match msg.get("digest") {
        Some(Value::Array(arr)) => {
            let v: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            if v.is_empty() {
                return Err(io::Error::other("digest array is empty"));
            }
            v
        }
        Some(Value::String(s)) => vec![s.as_str()],
        _ => return Err(io::Error::other("digest is required")),
    };

    let pin = auth_pin(msg);

    let mut reader = MynaReader::new()
        .and_then(|mut r| {
            r.timeout = Some(std::time::Duration::from_secs(5));
            r.connect()?;
            Ok(r)
        })
        .map_err(|e| io::Error::other(format!("failed to connect: {}", e)))?;
    let mut jpki = reader
        .jpki_ap()
        .map_err(|e| io::Error::other(format!("failed to select JPKI AP: {}", e)))?;

    jpki.verify(&KeyType::Sign, pin.as_deref().unwrap_or(""))
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut signatures = Vec::new();
    for digest_b64 in &digests_b64 {
        let digest = utils::base64_decode(digest_b64)
            .map_err(|e| io::Error::other(format!("failed to decode digest: {}", e)))?;
        let sig = jpki
            .pkey_sign(&KeyType::Sign, &digest)
            .map(|sig| utils::base64_encode(&sig))
            .map_err(|e| io::Error::other(format!("failed to sign digest: {}", e)))?;
        signatures.push(sig);
    }

    let cert = jpki
        .cert_read(&CertType::Sign)
        .map_err(|e| io::Error::other(format!("failed to load certificate: {}", e)))?;
    let certificate = cert
        .to_der()
        .map(|der| utils::base64_encode_nopad(der.as_slice()))
        .map_err(|e| io::Error::other(format!("failed to encode certificate: {}", e)))?;

    let manufacture_number = reader
        .unknown_ap()
        .and_then(|mut u| u.read_manufacture())
        .map_err(|e| io::Error::other(format!("failed to read manufacture number: {}", e)))?;
    let combination_code = generate_combination_code(&manufacture_number, uuid)?;

    let response = SignSuccessResponse {
        mode: "02".to_string(),
        result: "0".to_string(),
        uuid: uuid.to_string(),
        signature: signatures,
        certificate,
        combination_code: Some(combination_code),
    };
    send_message(&response)
}

fn text(msg: &Value) -> io::Result<()> {
    let config = load_config()?;
    let uuid = config["uuid"]
        .as_str()
        .ok_or_else(|| io::Error::other("uuid not found in config"))?;

    let service_id = msg.get("service_id").and_then(|v| v.as_str());

    if service_id != Some("01") {
        return Err(io::Error::other("Unsupported service_id"));
    }

    let pin = auth_pin(msg);

    let mut reader = MynaReader::new()
        .and_then(|mut r| {
            r.timeout = Some(std::time::Duration::from_secs(5));
            r.connect()?;
            Ok(r)
        })
        .map_err(|e| io::Error::other(format!("failed to connect: {}", e)))?;

    let mut text = reader
        .text_ap()
        .map_err(|e| io::Error::other(format!("failed to select Text AP: {}", e)))?;

    let attrs = text
        .attrs(pin.as_deref().unwrap_or(""))
        .map_err(|e| io::Error::other(format!("failed to read attrs: {}", e)))?;

    let manufacture_number = reader
        .unknown_ap()
        .and_then(|mut u| u.read_manufacture())
        .map_err(|e| io::Error::other(format!("failed to read manufacture number: {}", e)))?;
    let combination_code = generate_combination_code(&manufacture_number, uuid)?;

    let response = TextSuccessResponse {
        mode: "04".to_string(),
        result: "0".to_string(),
        uuid: uuid.to_string(),
        name: utils::hex_encode(attrs.name.as_bytes()),
        sex: utils::hex_encode(attrs.sex.as_bytes()),
        address: utils::hex_encode(attrs.addr.as_bytes()),
        birthday: utils::hex_encode(attrs.birth.as_bytes()),
        combination_code: Some(combination_code),
    };
    send_message(&response)
}

/// 受信したメッセージを処理する。戻り値がfalseの場合はループを終了する。
fn handle_message(msg: &Value) -> io::Result<bool> {
    let mode = msg.get("mode").and_then(|v| v.as_str());

    match mode {
        Some("check") => check::check()?,
        // JPKIユーザー認証
        Some("01") => auth(msg)?,
        // JPKIデジタル署名
        Some("02") => sign(msg)?,
        // 券面入力補助
        Some("04") => text(msg)?,
        Some("05") => {
            log::info!("received close request");
            return Ok(false);
        }
        _ => return Err(io::Error::other(format!("Unsupported mode {:?}", mode))),
    }
    Ok(true)
}

/// 起動時の状態をログに残す。
/// 引数はブラウザーによって異なり、Chromeは拡張機能のorigin、
/// Firefoxはmanifestのパスと拡張機能のIDを渡すため、呼び出し元の判別に使える。
fn log_startup() {
    let args: Vec<String> = std::env::args().collect();
    info!(
        "mpa {} started: pid={}, exe={:?}, args={:?}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        std::env::current_exe().ok(),
        args
    );
}

fn main() -> io::Result<()> {
    eprintln!("Host Application started");
    setup_logging().map_err(io::Error::other)?;
    setup_panic_hook();
    log_startup();

    loop {
        let msg = match recv_message() {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                info!("stdin closed, shutting down");
                break;
            }
            Err(e) => {
                send_error(format!("failed to receive message: {}", e))?;
                break;
            }
        };

        // 応答を返さずにプロセスが終了するとブラウザー側では原因が分からない
        // (Firefoxでは "An unexpected error occurred" となる) ため、
        // エラーは必ず応答として返す
        match handle_message(&msg) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => send_error(e.to_string())?,
        }
    }
    info!("exit");
    Ok(())
}
