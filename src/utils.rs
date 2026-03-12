/// 共通ユーティリティ関数
use crate::error::Error;

pub fn base64_decode(input: &str) -> Result<Vec<u8>, Error> {
    openssl::base64::decode_block(input).map_err(|e| Error::with_source("base64 decode failed", e))
}

pub fn base64_encode(input: &[u8]) -> String {
    openssl::base64::encode_block(input)
}

pub fn base64_encode_nopad(input: &[u8]) -> String {
    openssl::base64::encode_block(input)
        .trim_end_matches('=')
        .to_string()
}

/// パスワード/PINの入力を取得する共通関数
pub fn prompt_input(prompt: &str, existing: &Option<String>) -> String {
    match existing {
        Some(v) => v.clone(),
        None => crate::prompt::password_masked(prompt).unwrap(),
    }
}

/// 4桁暗証番号のバリデーション
pub fn validate_4digit_pin(pin: &str) -> Result<(), Error> {
    if pin.len() != 4 || !pin.chars().all(|c| c.is_ascii_digit()) {
        Err("暗証番号(4桁)を入力してください。".into())
    } else {
        Ok(())
    }
}

/// JPKI署名用パスワードのバリデーション(6-16桁、英大文字+数字)
pub fn validate_jpki_sign_password(pass: &str) -> Result<(), Error> {
    if pass.len() < 6 || pass.len() > 16 {
        return Err("パスワードの長さが正しくありません(6-16桁)".into());
    }
    if !pass
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Err("パスワードの文字種が不正です(英大文字と数字のみ)".into());
    }
    Ok(())
}
