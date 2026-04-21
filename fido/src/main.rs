use chrono::Local;
use ed25519_dalek::{Signer, SigningKey};
use fern::Dispatch;
use log::{LevelFilter, info};
use myna::jpki::KeyType;
use myna::reader::MynaReader;
use myna::utils;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};

const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

#[derive(Serialize)]
struct DeriveResponse {
    result: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
}

#[derive(Serialize)]
struct SignResponse {
    result: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
    signature: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    result: String,
    message: String,
}

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
    let masked_raw = serde_json::to_string(&masked)
        .unwrap_or_else(|_| raw.trim_end_matches(['\r', '\n']).to_string());
    info!("recv: {}", masked_raw);

    Ok(val)
}

fn send_message<T: Serialize>(msg: &T) -> io::Result<()> {
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

fn send_error(message: String) -> io::Result<()> {
    log::error!("{}", message);
    send_message(&ErrorResponse {
        result: "1".to_string(),
        message,
    })
}

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

/// (rpId, userId) → Ed25519 鍵ペア
/// 1. input = DER(rpId, userId)
/// 2. digest_info = SHA-256 DigestInfo of SHA-256(input)
/// 3. rsa_sig = pkey_sign(Auth, digest_info)
/// 4. seed = SHA-256(rsa_sig)
/// 5. Ed25519 keypair from seed
fn derive_signing_key(pin: &str, rp_id: &str, user_id: &[u8]) -> Result<SigningKey, String> {
    let mut reader = MynaReader::new()
        .and_then(|mut r| {
            r.timeout = Some(std::time::Duration::from_secs(5));
            r.connect()?;
            Ok(r)
        })
        .map_err(|e| format!("ICカードの接続に失敗しました: {}", e))?;

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

fn read_pin(msg: &Value) -> Option<String> {
    msg.get("pin")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

fn read_str_field<'a>(msg: &'a Value, key: &str) -> Option<&'a str> {
    msg.get(key).and_then(|v| v.as_str())
}

fn decode_b64_field(msg: &Value, key: &str) -> Result<Vec<u8>, String> {
    let s = read_str_field(msg, key).ok_or_else(|| format!("{}が指定されていません", key))?;
    utils::base64_decode(s).map_err(|e| format!("{}のbase64デコードに失敗しました: {}", key, e))
}

fn handle_derive(msg: &Value) -> io::Result<()> {
    let pin = match read_pin(msg) {
        Some(p) => p,
        None => return send_error("pinが指定されていません".to_string()),
    };
    let rp_id = match read_str_field(msg, "rpId") {
        Some(s) => s,
        None => return send_error("rpIdが指定されていません".to_string()),
    };
    let user_id = match decode_b64_field(msg, "userId") {
        Ok(v) => v,
        Err(e) => return send_error(e),
    };

    let signing_key = match derive_signing_key(&pin, rp_id, &user_id) {
        Ok(k) => k,
        Err(e) => return send_error(e),
    };

    let public_key = signing_key.verifying_key().to_bytes();
    let credential_id: [u8; 32] = Sha256::digest(public_key).into();

    send_message(&DeriveResponse {
        result: "0".to_string(),
        public_key: utils::base64_encode(&public_key),
        credential_id: utils::base64_encode(&credential_id),
    })
}

fn handle_sign(msg: &Value) -> io::Result<()> {
    let pin = match read_pin(msg) {
        Some(p) => p,
        None => return send_error("pinが指定されていません".to_string()),
    };
    let rp_id = match read_str_field(msg, "rpId") {
        Some(s) => s,
        None => return send_error("rpIdが指定されていません".to_string()),
    };
    let user_id = match decode_b64_field(msg, "userId") {
        Ok(v) => v,
        Err(e) => return send_error(e),
    };
    let message = match decode_b64_field(msg, "message") {
        Ok(v) => v,
        Err(e) => return send_error(e),
    };

    let signing_key = match derive_signing_key(&pin, rp_id, &user_id) {
        Ok(k) => k,
        Err(e) => return send_error(e),
    };

    let public_key = signing_key.verifying_key().to_bytes();
    let credential_id: [u8; 32] = Sha256::digest(public_key).into();
    let signature = signing_key.sign(&message).to_bytes();

    send_message(&SignResponse {
        result: "0".to_string(),
        public_key: utils::base64_encode(&public_key),
        credential_id: utils::base64_encode(&credential_id),
        signature: utils::base64_encode(&signature),
    })
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
