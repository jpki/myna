use chrono::Local;
use ed25519_dalek::{Signer, SigningKey};
use fern::Dispatch;
use log::{LevelFilter, info};
use myna::jpki::KeyType;
use myna::reader::MynaReader;
use myna::utils;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::time::Duration;

const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const RESULT_OK: &str = "0";
const RESULT_ERR: &str = "1";

// ============================================================
// Request / Response 型
// ============================================================

#[derive(Deserialize)]
struct DeriveReq {
    pin: String,
    #[serde(rename = "rpId")]
    rp_id: String,
    #[serde(rename = "userId")]
    user_id_b64: String,
}

#[derive(Deserialize)]
struct SignReq {
    pin: String,
    #[serde(rename = "rpId")]
    rp_id: String,
    #[serde(rename = "userId")]
    user_id_b64: String,
    #[serde(rename = "message")]
    message_b64: String,
}

#[derive(Serialize)]
struct DeriveResponse {
    result: &'static str,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
}

#[derive(Serialize)]
struct SignResponse {
    result: &'static str,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
    signature: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    result: &'static str,
    message: String,
}

// ============================================================
// Native Messaging I/O
// ============================================================

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

    let mut masked = val.clone();
    if let Some(obj) = masked.as_object_mut() {
        obj.remove("pin");
    }
    info!("recv: {}", masked);

    Ok(val)
}

fn send_message<T: Serialize>(msg: &T) -> io::Result<()> {
    let data = serde_json::to_vec(msg)?;
    info!("send: {}", String::from_utf8_lossy(&data));

    let len = (data.len() as u32).to_le_bytes();
    let mut stdout = io::stdout().lock();
    stdout.write_all(&len)?;
    stdout.write_all(&data)?;
    stdout.flush()
}

fn send_error(message: impl Into<String>) -> io::Result<()> {
    let message = message.into();
    log::error!("{}", message);
    send_message(&ErrorResponse {
        result: RESULT_ERR,
        message,
    })
}

// ============================================================
// DER エンコード (KeyDerivationInput)
// ============================================================

fn der_encode_length(len: usize, buf: &mut Vec<u8>) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_encode_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

/// SEQUENCE { UTF8String rpId, OCTET STRING userId }
fn key_derivation_input(rp_id: &str, user_id: &[u8]) -> Vec<u8> {
    let rp_id_tlv = der_tlv(0x0c, rp_id.as_bytes());
    let user_id_tlv = der_tlv(0x04, user_id);
    let mut inner = Vec::with_capacity(rp_id_tlv.len() + user_id_tlv.len());
    inner.extend_from_slice(&rp_id_tlv);
    inner.extend_from_slice(&user_id_tlv);
    der_tlv(0x30, &inner)
}

fn build_digest_info(message: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(message);
    let mut out = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    out.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    out.extend_from_slice(&hash);
    out
}

// ============================================================
// 鍵導出
// ============================================================

/// (rpId, userId) → Ed25519 鍵ペア
fn derive_signing_key(pin: &str, rp_id: &str, user_id: &[u8]) -> Result<SigningKey, String> {
    let connect_err = |e| format!("ICカードの接続に失敗しました: {}", e);

    let mut reader = MynaReader::new().map_err(connect_err)?;
    reader.timeout = Some(Duration::from_secs(5));
    reader.connect().map_err(connect_err)?;

    let mut jpki = reader
        .jpki_ap()
        .map_err(|e| format!("JPKI APの選択に失敗しました: {}", e))?;

    jpki.verify(&KeyType::Auth, pin)
        .map_err(|e| e.to_string())?;

    let input = key_derivation_input(rp_id, user_id);
    let digest_info = build_digest_info(&input);

    let rsa_sig = jpki
        .pkey_sign(&KeyType::Auth, &digest_info)
        .map_err(|e| format!("RSA署名に失敗しました: {}", e))?;

    let seed: [u8; 32] = Sha256::digest(&rsa_sig).into();
    Ok(SigningKey::from_bytes(&seed))
}

// ============================================================
// ハンドラ
// ============================================================

fn parse_req<T: for<'de> Deserialize<'de>>(msg: &Value) -> Result<T, String> {
    serde_json::from_value(msg.clone())
        .map_err(|e| format!("リクエストの解析に失敗しました: {}", e))
}

fn decode_b64(field: &str, b64: &str) -> Result<Vec<u8>, String> {
    utils::base64_decode(b64).map_err(|e| format!("{}のbase64デコードに失敗しました: {}", field, e))
}

fn process_derive(msg: &Value) -> Result<DeriveResponse, String> {
    let req: DeriveReq = parse_req(msg)?;
    let user_id = decode_b64("userId", &req.user_id_b64)?;

    let signing_key = derive_signing_key(&req.pin, &req.rp_id, &user_id)?;
    let public_key = signing_key.verifying_key().to_bytes();
    let credential_id: [u8; 32] = Sha256::digest(public_key).into();

    Ok(DeriveResponse {
        result: RESULT_OK,
        public_key: utils::base64_encode(&public_key),
        credential_id: utils::base64_encode(&credential_id),
    })
}

fn process_sign(msg: &Value) -> Result<SignResponse, String> {
    let req: SignReq = parse_req(msg)?;
    let user_id = decode_b64("userId", &req.user_id_b64)?;
    let message = decode_b64("message", &req.message_b64)?;

    let signing_key = derive_signing_key(&req.pin, &req.rp_id, &user_id)?;
    let public_key = signing_key.verifying_key().to_bytes();
    let credential_id: [u8; 32] = Sha256::digest(public_key).into();
    let signature = signing_key.sign(&message).to_bytes();

    Ok(SignResponse {
        result: RESULT_OK,
        public_key: utils::base64_encode(&public_key),
        credential_id: utils::base64_encode(&credential_id),
        signature: utils::base64_encode(&signature),
    })
}

fn handle_derive(msg: &Value) -> io::Result<()> {
    match process_derive(msg) {
        Ok(res) => send_message(&res),
        Err(e) => send_error(e),
    }
}

fn handle_sign(msg: &Value) -> io::Result<()> {
    match process_sign(msg) {
        Ok(res) => send_message(&res),
        Err(e) => send_error(e),
    }
}

// ============================================================
// ロギング
// ============================================================

fn setup_logging() -> Result<(), fern::InitError> {
    let mut dispatch = Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(LevelFilter::Info);

    if let Some(log_path) = std::env::var_os("MYNA_FIDO_LOG") {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        dispatch = dispatch.chain(log_file);
    } else if !cfg!(debug_assertions) {
        return Ok(());
    } else {
        dispatch = dispatch.chain(io::stderr());
    }

    dispatch.apply()?;
    Ok(())
}

fn main() -> io::Result<()> {
    setup_logging().map_err(io::Error::other)?;
    info!("myna-fido started");
    loop {
        let msg = match recv_message() {
            Ok(msg) => msg,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        let mode = msg.get("mode").and_then(|v| v.as_str());
        match mode {
            Some("derive") => handle_derive(&msg)?,
            Some("sign") => handle_sign(&msg)?,
            _ => send_error(format!("Unsupported mode {:?}", mode))?,
        }
    }
    Ok(())
}
