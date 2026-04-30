/// PDF電子署名(PAdES/PKCS#7 detached)の実装
///
/// マイナンバーカードのJPKI署名用鍵でPDFにインクリメンタル追記で電子署名を埋め込む。
use crate::error::Error;
use crate::utils;
use crate::verify;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use flate2::read::ZlibDecoder;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

/// /Contents プレースホルダのバイトサイズ (hex で 16384 文字 = 8192 バイト)
const SIG_CONTENTS_SIZE: usize = 8192;

// ---------------------------------------------------------------------------
// PDF 簡易パーサーユーティリティ
// ---------------------------------------------------------------------------

/// ファイル末尾から `startxref` を探し、xref オフセットを返す
fn find_startxref(data: &[u8]) -> Option<usize> {
    let tail = if data.len() > 1024 {
        &data[data.len() - 1024..]
    } else {
        data
    };
    let needle = b"startxref";
    let pos = tail.windows(needle.len()).rposition(|w| w == needle)?;
    let after = &tail[pos + needle.len()..];
    let s = std::str::from_utf8(after).ok()?;
    let num_str = s.split_whitespace().next()?;
    num_str.parse::<usize>().ok()
}

/// xref テーブルを解析して、最大オブジェクト ID を返す
fn find_max_obj_id(data: &[u8], xref_offset: usize) -> usize {
    let mut max_id: usize = 0;
    let mut offset = xref_offset;
    let mut visited = std::collections::HashSet::new();

    loop {
        if !visited.insert(offset) {
            break;
        }
        let slice = &data[offset..];
        if slice.starts_with(b"xref") {
            // 通常の xref テーブル — "trailer" までをテキスト解析
            let trailer_pos = slice
                .windows(7)
                .position(|w| w == b"trailer")
                .unwrap_or(slice.len());
            let xref_text = String::from_utf8_lossy(&slice[4..trailer_pos]);
            for line in xref_text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 2
                    && let (Ok(start), Ok(count)) =
                        (parts[0].parse::<usize>(), parts[1].parse::<usize>())
                {
                    let end = start + count;
                    if end > max_id {
                        max_id = end;
                    }
                }
            }
        } else {
            // xref stream: オブジェクトID自体 + /Size から max を取得
            let dict = get_xref_dict_text(data, offset);
            if let Some(ref text) = dict {
                let obj_id_str: String = slice
                    .iter()
                    .take_while(|&&b| b.is_ascii_digit())
                    .map(|&b| b as char)
                    .collect();
                if let Ok(id) = obj_id_str.parse::<usize>()
                    && id + 1 > max_id
                {
                    max_id = id + 1;
                }
                if let Some(size) = extract_int_value(text, "/Size")
                    && size > max_id
                {
                    max_id = size;
                }
            }
        }

        // /Prev を探す
        let dict = get_xref_dict_text(data, offset);
        if let Some(ref text) = dict
            && let Some(prev) = extract_int_value(text, "/Prev")
        {
            offset = prev;
            continue;
        }
        break;
    }

    max_id
}

/// trailer 辞書から指定キーの整数値を抽出
fn extract_int_value(text: &str, key: &str) -> Option<usize> {
    let pos = text.find(key)?;
    let after = &text[pos + key.len()..];
    let s = after.trim_start();
    let num: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if num.is_empty() {
        None
    } else {
        num.parse().ok()
    }
}

/// trailer 辞書からオブジェクト参照 (`N 0 R`) を抽出
fn extract_ref_value(text: &str, key: &str) -> Option<usize> {
    let pos = text.find(key)?;
    let after = &text[pos + key.len()..];
    let s = after.trim_start();
    let num: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

/// xref 位置から辞書テキストを取得（traditional trailer と xref stream の両方に対応）
///
/// xref stream の場合、stream キーワード以降にバイナリデータが含まれるため
/// バイト列レベルで辞書範囲を特定してからテキスト変換する。
fn get_xref_dict_text(data: &[u8], xref_offset: usize) -> Option<String> {
    let slice = &data[xref_offset..];

    // 通常の xref テーブルの場合のみ "trailer" を検索
    if slice.starts_with(b"xref")
        && let Some(pos) = slice.windows(7).position(|w| w == b"trailer")
    {
        let trailer_slice = &slice[pos..];
        let end = trailer_slice
            .windows(2)
            .position(|w| w == b">>")
            .map(|p| p + 2)
            .unwrap_or(std::cmp::min(trailer_slice.len(), 1024));
        return Some(String::from_utf8_lossy(&trailer_slice[..end]).to_string());
    }

    // xref stream: "N 0 obj\n<< ... >>\nstream" の辞書部分を取得
    // ネストされた << >> を考慮して対応する >> を探す
    let dict_start = slice.windows(2).position(|w| w == b"<<")?;
    let mut depth = 0;
    let mut i = dict_start;
    while i + 1 < slice.len() {
        if slice[i] == b'<' && slice[i + 1] == b'<' {
            depth += 1;
            i += 2;
        } else if slice[i] == b'>' && slice[i + 1] == b'>' {
            depth -= 1;
            if depth == 0 {
                let dict_end = i + 2;
                return Some(String::from_utf8_lossy(&slice[dict_start..dict_end]).to_string());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

/// /Root 参照を取得
fn find_root_ref(data: &[u8], xref_offset: usize) -> Option<usize> {
    let dict = get_xref_dict_text(data, xref_offset)?;
    extract_ref_value(&dict, "/Root")
}

/// /Size を取得
fn find_trailer_size(data: &[u8], xref_offset: usize) -> Option<usize> {
    let dict = get_xref_dict_text(data, xref_offset)?;
    extract_int_value(&dict, "/Size")
}

/// /Info 参照を取得
fn find_info_ref(data: &[u8], xref_offset: usize) -> Option<usize> {
    let dict = get_xref_dict_text(data, xref_offset)?;
    extract_ref_value(&dict, "/Info")
}

/// 指定オブジェクトIDの内容を検索して返す（非圧縮オブジェクト）
///
/// PDF ではトークン間にスペース・改行(\n)・CR(\r) が使われるため、
/// "N 0 obj" だけでなく "N\n0\nobj" 等にも対応する。
fn find_object_content(data: &[u8], obj_id: usize) -> Option<String> {
    let id_bytes = obj_id.to_string().into_bytes();
    let mut i = 0;
    while i + id_bytes.len() < data.len() {
        // オブジェクト ID 部分が一致するか
        if &data[i..i + id_bytes.len()] == id_bytes.as_slice()
            && (i == 0 || matches!(data[i - 1], b'\n' | b'\r' | b' '))
        {
            // ID の後に空白+ "0" +空白+ "obj" が続くか
            let rest = &data[i + id_bytes.len()..];
            if let Some(obj_start) = match_obj_header(rest) {
                let content_start = i + id_bytes.len() + obj_start;
                let content = &data[content_start..];
                if let Some(end_pos) = content.windows(6).position(|w| w == b"endobj") {
                    return Some(
                        String::from_utf8_lossy(&data[content_start..content_start + end_pos])
                            .to_string(),
                    );
                }
            }
        }
        i += 1;
    }
    None
}

/// " 0 obj" のようなヘッダー部分をマッチし、"obj" の直後のオフセットを返す。
/// 空白は 0x20, 0x0A, 0x0D のいずれか。
fn match_obj_header(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    // 1つ以上の空白
    if pos >= data.len() || !matches!(data[pos], b' ' | b'\n' | b'\r') {
        return None;
    }
    while pos < data.len() && matches!(data[pos], b' ' | b'\n' | b'\r') {
        pos += 1;
    }
    // "0"
    if pos >= data.len() || data[pos] != b'0' {
        return None;
    }
    pos += 1;
    // 1つ以上の空白
    if pos >= data.len() || !matches!(data[pos], b' ' | b'\n' | b'\r') {
        return None;
    }
    while pos < data.len() && matches!(data[pos], b' ' | b'\n' | b'\r') {
        pos += 1;
    }
    // "obj"
    if pos + 3 > data.len() || &data[pos..pos + 3] != b"obj" {
        return None;
    }
    pos += 3;
    Some(pos)
}

/// 圧縮オブジェクトストリームから指定オブジェクトの内容を取得
fn find_object_in_objstm(data: &[u8], target_obj_id: usize) -> Option<String> {
    // /Type/ObjStm または /Type /ObjStm を持つオブジェクトを検索
    let mut pos = 0;
    while pos < data.len() {
        // ObjStm パターンを検索
        let found = find_bytes(data, b"/Type/ObjStm", pos)
            .or_else(|| find_bytes(data, b"/Type /ObjStm", pos));

        let objstm_pos = match found {
            Some(p) => p,
            None => break,
        };

        // このオブジェクトの辞書 << ... >> を見つける
        let dict_start = match find_bytes_rev(data, b"<<", objstm_pos) {
            Some(p) => p,
            None => {
                pos = objstm_pos + 1;
                continue;
            }
        };
        let dict_slice = &data[dict_start..];
        let dict_end_rel = match dict_slice.windows(2).position(|w| w == b">>") {
            Some(p) => p,
            None => {
                pos = objstm_pos + 1;
                continue;
            }
        };
        let dict_end = dict_start + dict_end_rel + 2;
        let dict_text = String::from_utf8_lossy(&data[dict_start..dict_end]);

        let _n = match extract_int_value(&dict_text, "/N") {
            Some(v) => v,
            None => {
                pos = objstm_pos + 1;
                continue;
            }
        };
        let first = match extract_int_value(&dict_text, "/First") {
            Some(v) => v,
            None => {
                pos = objstm_pos + 1;
                continue;
            }
        };
        let length = match extract_int_value(&dict_text, "/Length") {
            Some(v) => v,
            None => {
                pos = objstm_pos + 1;
                continue;
            }
        };

        // stream データの開始位置を特定
        let stream_kw_pos = match find_bytes(data, b"stream", dict_end) {
            Some(p) => p,
            None => {
                pos = objstm_pos + 1;
                continue;
            }
        };
        let mut stream_start = stream_kw_pos + 6; // "stream" の後
        // \r\n or \n をスキップ
        if stream_start < data.len() && data[stream_start] == b'\r' {
            stream_start += 1;
        }
        if stream_start < data.len() && data[stream_start] == b'\n' {
            stream_start += 1;
        }

        if stream_start + length > data.len() {
            pos = objstm_pos + 1;
            continue;
        }
        let stream_data = &data[stream_start..stream_start + length];

        // FlateDecode で展開
        let decompressed = match decompress_flate(stream_data) {
            Some(d) => d,
            None => {
                pos = objstm_pos + 1;
                continue;
            }
        };

        if first > decompressed.len() {
            pos = objstm_pos + 1;
            continue;
        }

        // インデックス部分を解析（先頭 first バイトに N 組の整数ペア）
        let index_text = String::from_utf8_lossy(&decompressed[..first]);
        let nums: Vec<usize> = index_text
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();

        // ターゲットオブジェクトを検索
        for i in (0..nums.len()).step_by(2) {
            if i + 1 >= nums.len() {
                break;
            }
            let obj_id = nums[i];
            let obj_offset = nums[i + 1];

            if obj_id == target_obj_id {
                let abs_offset = first + obj_offset;
                // 次のオブジェクトのオフセットまたは末尾
                let next_offset = if i + 3 < nums.len() {
                    first + nums[i + 3]
                } else {
                    decompressed.len()
                };
                if abs_offset <= decompressed.len() {
                    let end = std::cmp::min(next_offset, decompressed.len());
                    let obj_data = &decompressed[abs_offset..end];
                    return Some(String::from_utf8_lossy(obj_data).to_string());
                }
            }
        }

        pos = objstm_pos + 1;
    }
    None
}

/// zlib (FlateDecode) 展開
fn decompress_flate(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// バイト列の前方検索
fn find_bytes(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= data.len() {
        return None;
    }
    data[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// バイト列の後方検索
fn find_bytes_rev(data: &[u8], needle: &[u8], before: usize) -> Option<usize> {
    let end = std::cmp::min(before, data.len());
    data[..end].windows(needle.len()).rposition(|w| w == needle)
}

/// オブジェクトの辞書内容を取得（非圧縮 → 圧縮オブジェクトストリームの順に検索）
fn get_object_dict(data: &[u8], obj_id: usize) -> Option<String> {
    find_object_content(data, obj_id).or_else(|| find_object_in_objstm(data, obj_id))
}

/// 辞書テキストから内部コンテンツを抽出（最外側の << >> を除去）
/// ネストされた << >> を正しく処理する
fn extract_dict_inner(text: &str) -> &str {
    let text = text.trim();
    // 最初の << を見つける
    let start = match text.find("<<") {
        Some(p) => p + 2,
        None => return text,
    };
    // ネスト対応で最後の >> を見つける
    let bytes = text.as_bytes();
    let mut depth = 1;
    let mut i = start;
    while i < bytes.len().saturating_sub(1) {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            depth += 1;
            i += 2;
        } else if bytes[i] == b'>' && bytes[i + 1] == b'>' {
            depth -= 1;
            if depth == 0 {
                return &text[start..i];
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    &text[start..]
}

/// 辞書テキストに /AcroForm エントリを追加した新しい Root 辞書を構築
fn build_updated_root_dict(original: &str, acroform_obj_id: usize) -> String {
    let inner = extract_dict_inner(original);

    // 既存の /AcroForm を削除（あれば）
    let cleaned = remove_dict_key(inner, "/AcroForm");

    format!(
        "<<\n{}\n/AcroForm {} 0 R\n>>",
        cleaned.trim(),
        acroform_obj_id
    )
}

/// 辞書テキストから指定キーのエントリを除去
fn remove_dict_key(dict_inner: &str, key: &str) -> String {
    let Some(key_pos) = dict_inner.find(key) else {
        return dict_inner.to_string();
    };

    let before = &dict_inner[..key_pos];
    let after = &dict_inner[key_pos + key.len()..];

    // 値部分をスキップ（次のキー '/' または辞書終端まで）
    let value_end = skip_pdf_value(after);
    let rest = &after[value_end..];

    format!("{}{}", before, rest)
}

/// PDF 値を1つスキップして、次のトークン開始位置を返す
fn skip_pdf_value(s: &str) -> usize {
    let s = s.trim_start();
    let offset = s.as_ptr() as usize - s.trim_start().as_ptr() as usize;
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return s.len();
    }

    let skip = match bytes[0] {
        // 辞書 << ... >>
        b'<' if bytes.len() > 1 && bytes[1] == b'<' => {
            let mut depth = 1;
            let mut i = 2;
            while i < bytes.len().saturating_sub(1) {
                if bytes[i] == b'<' && bytes[i + 1] == b'<' {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'>' && bytes[i + 1] == b'>' {
                    depth -= 1;
                    if depth == 0 {
                        return offset + (s.len() - bytes.len()) + i + 2;
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            bytes.len()
        }
        // 配列 [ ... ]
        b'[' => {
            let mut depth = 1;
            let mut i = 1;
            while i < bytes.len() {
                if bytes[i] == b'[' {
                    depth += 1;
                } else if bytes[i] == b']' {
                    depth -= 1;
                    if depth == 0 {
                        return offset + (s.len() - bytes.len()) + i + 1;
                    }
                }
                i += 1;
            }
            bytes.len()
        }
        // 文字列 ( ... )
        b'(' => {
            let mut depth = 1;
            let mut i = 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'(' {
                    depth += 1;
                } else if bytes[i] == b')' {
                    depth -= 1;
                    if depth == 0 {
                        return offset + (s.len() - bytes.len()) + i + 1;
                    }
                }
                i += 1;
            }
            bytes.len()
        }
        // 参照 N G R やその他のトークン
        _ => {
            // "N G R" のパターンかトークン
            // 次の '/' か空白+次のキーまでスキップ
            let rest = s;
            // 参照パターン: 数字 空白 数字 空白 R
            if bytes[0].is_ascii_digit() {
                // "N G R" 参照の可能性をチェック
                if let Some(r_end) = find_ref_end(rest) {
                    return offset + (s.len() - bytes.len()) + r_end;
                }
            }
            // それ以外: 次の行頭 '/' か行末まで
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'\n' || bytes[i] == b'\r' {
                    return offset + (s.len() - bytes.len()) + i;
                }
                i += 1;
            }
            bytes.len()
        }
    };
    offset + (s.len() - bytes.len()) + skip
}

/// "N G R" 参照パターンの終端を検出
fn find_ref_end(s: &str) -> Option<usize> {
    let mut chars = s.char_indices();
    // 最初の数字列
    let mut last_pos = 0;
    for (i, c) in chars.by_ref() {
        if !c.is_ascii_digit() {
            last_pos = i;
            break;
        }
    }
    // 空白
    let rest = &s[last_pos..];
    let trimmed = rest.trim_start();
    let ws_len = rest.len() - trimmed.len();
    if ws_len == 0 {
        return None;
    }
    // 2つ目の数字列
    let rest = trimmed;
    let digit_end = rest
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| i)
        .unwrap_or(rest.len());
    if digit_end == 0 {
        return None;
    }
    let rest = &rest[digit_end..];
    let trimmed = rest.trim_start();
    // 'R'
    if trimmed.starts_with('R')
        && (trimmed.len() == 1 || !trimmed.as_bytes()[1].is_ascii_alphanumeric())
    {
        let total = s.len() - trimmed.len() + 1;
        Some(total)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// PDF 署名
// ---------------------------------------------------------------------------

/// /Contents の位置情報
pub struct ContentsRange {
    /// '<' の位置
    pub angle_start: usize,
    /// '>' の次の位置
    pub angle_end: usize,
    /// hex 文字列の開始位置
    pub hex_start: usize,
    /// hex 文字列の終了位置
    pub hex_end: usize,
    /// Sig辞書オブジェクトのオフセット (ByteRange検索用)
    sig_obj_offset: usize,
}

/// PDF にプレースホルダ付き署名辞書を追記したバイト列を返す
pub fn build_pdf_with_placeholder(original: &[u8]) -> Result<Vec<u8>, Error> {
    let xref_offset =
        find_startxref(original).ok_or_else(|| Error::from("startxref が見つかりません"))?;
    let root_ref = find_root_ref(original, xref_offset)
        .ok_or_else(|| Error::from("/Root が見つかりません"))?;
    let trailer_size = find_trailer_size(original, xref_offset)
        .ok_or_else(|| Error::from("/Size が見つかりません"))?;
    let info_ref = find_info_ref(original, xref_offset);
    let max_id = find_max_obj_id(original, xref_offset);
    let next_id = std::cmp::max(max_id, trailer_size);

    let root_dict_text = get_object_dict(original, root_ref)
        .ok_or_else(|| Error::from("Root カタログオブジェクトが見つかりません"))?;

    let sig_obj_id = next_id;
    let widget_obj_id = next_id + 1;
    let acroform_obj_id = next_id + 2;
    let updated_root_id = root_ref;
    let new_size = next_id + 3;

    let placeholder_hex = "0".repeat(SIG_CONTENTS_SIZE * 2);
    let byterange_placeholder = format!("[{:<10} {:<10} {:<10} {:<10}]", 0, 0, 0, 0);

    let mut append = Vec::new();
    append.push(b'\n');

    let sig_obj_offset = original.len() + append.len();
    let sig_obj = format!(
        "{} 0 obj\n<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n/ByteRange {}\n/Contents <{}>\n/Reason (JPKI Digital Signature)\n>>\nendobj\n",
        sig_obj_id, byterange_placeholder, placeholder_hex
    );
    append.extend(sig_obj.as_bytes());

    let widget_obj_offset = original.len() + append.len();
    let widget_obj = format!(
        "{} 0 obj\n<<\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/Rect [0 0 0 0]\n/V {} 0 R\n/T (Sig1)\n/F 132\n>>\nendobj\n",
        widget_obj_id, sig_obj_id
    );
    append.extend(widget_obj.as_bytes());

    let acroform_obj_offset = original.len() + append.len();
    let acroform_obj = format!(
        "{} 0 obj\n<<\n/Fields [{} 0 R]\n/SigFlags 3\n>>\nendobj\n",
        acroform_obj_id, widget_obj_id
    );
    append.extend(acroform_obj.as_bytes());

    let updated_root_offset = original.len() + append.len();
    let updated_root_dict = build_updated_root_dict(&root_dict_text, acroform_obj_id);
    let updated_root_obj = format!("{} 0 obj\n{}\nendobj\n", updated_root_id, updated_root_dict);
    append.extend(updated_root_obj.as_bytes());

    let new_xref_offset = original.len() + append.len();
    let mut xref = String::new();
    xref.push_str("xref\n");
    xref.push_str(&format!("{} 1\n", updated_root_id));
    xref.push_str(&format!("{:010} 00000 n \n", updated_root_offset));
    xref.push_str(&format!("{} 3\n", sig_obj_id));
    xref.push_str(&format!("{:010} 00000 n \n", sig_obj_offset));
    xref.push_str(&format!("{:010} 00000 n \n", widget_obj_offset));
    xref.push_str(&format!("{:010} 00000 n \n", acroform_obj_offset));
    append.extend(xref.as_bytes());

    let mut trailer = String::new();
    trailer.push_str("trailer\n<<\n");
    trailer.push_str(&format!("/Size {}\n", new_size));
    trailer.push_str(&format!("/Root {} 0 R\n", root_ref));
    if let Some(info) = info_ref {
        trailer.push_str(&format!("/Info {} 0 R\n", info));
    }
    trailer.push_str(&format!("/Prev {}\n", xref_offset));
    trailer.push_str(">>\n");
    trailer.push_str("startxref\n");
    trailer.push_str(&format!("{}\n", new_xref_offset));
    trailer.push_str("%%EOF\n");
    append.extend(trailer.as_bytes());

    let mut output = original.to_vec();
    output.extend(&append);
    Ok(output)
}

/// /Contents と ByteRange プレースホルダの位置を特定する
pub fn locate_signature_placeholders(output: &[u8]) -> Result<(ContentsRange, Vec<u8>), Error> {
    // 末尾から Sig 辞書を探す: 最後の /Type /Sig を検索
    let needle = b"/Type /Sig";
    let sig_dict_pos = output
        .windows(needle.len())
        .rposition(|w| w == needle)
        .ok_or_else(|| Error::from("/Type /Sig が見つかりません"))?;
    // Sig辞書のオブジェクト開始を探す
    let sig_obj_offset = find_bytes_rev(output, b" 0 obj", sig_dict_pos)
        .map(|p| {
            // 数字の先頭まで戻る
            let mut start = p;
            while start > 0 && output[start - 1].is_ascii_digit() {
                start -= 1;
            }
            start
        })
        .ok_or_else(|| Error::from("Sig オブジェクトの開始が見つかりません"))?;

    let contents_hex_start = find_contents_hex_start(output, sig_obj_offset)
        .ok_or_else(|| Error::from("/Contents プレースホルダが見つかりません"))?;
    let contents_hex_end = contents_hex_start + SIG_CONTENTS_SIZE * 2;
    let angle_start = contents_hex_start - 1;
    let angle_end = contents_hex_end + 1;

    let byterange_placeholder = format!("[{:<10} {:<10} {:<10} {:<10}]", 0, 0, 0, 0).into_bytes();

    Ok((
        ContentsRange {
            angle_start,
            angle_end,
            hex_start: contents_hex_start,
            hex_end: contents_hex_end,
            sig_obj_offset,
        },
        byterange_placeholder,
    ))
}

/// ByteRange をプレースホルダに上書き
pub fn write_byte_range(
    output: &mut [u8],
    contents: &ContentsRange,
    byterange_placeholder: &[u8],
) -> Result<(), Error> {
    let byte_range = format!(
        "[{:<10} {:<10} {:<10} {:<10}]",
        0,
        contents.angle_start,
        contents.angle_end,
        output.len() - contents.angle_end
    );

    let br_pos = output[contents.sig_obj_offset..]
        .windows(byterange_placeholder.len())
        .position(|w| w == byterange_placeholder)
        .ok_or_else(|| Error::from("ByteRange プレースホルダが見つかりません"))?
        + contents.sig_obj_offset;
    output[br_pos..br_pos + byte_range.len()].copy_from_slice(byte_range.as_bytes());
    Ok(())
}

/// ByteRange 区間のハッシュ (SHA-256) を計算
pub fn hash_signed_ranges(output: &[u8], contents: &ContentsRange) -> Result<Vec<u8>, Error> {
    let range1 = &output[0..contents.angle_start];
    let range2 = &output[contents.angle_end..];
    let hash = Sha256::new()
        .chain_update(range1)
        .chain_update(range2)
        .finalize();
    Ok(hash.to_vec())
}

/// PKCS#7 DER を /Contents に埋め込み
pub fn embed_signature(
    output: &mut [u8],
    contents: &ContentsRange,
    pkcs7_der: &[u8],
) -> Result<(), Error> {
    let sig_hex = utils::hex_encode(pkcs7_der);
    if sig_hex.len() > SIG_CONTENTS_SIZE * 2 {
        return Err(Error::from(format!(
            "署名データがプレースホルダサイズを超えています ({} > {})",
            sig_hex.len(),
            SIG_CONTENTS_SIZE * 2
        )));
    }
    let padded_hex = format!("{:0<width$}", sig_hex, width = SIG_CONTENTS_SIZE * 2);
    output[contents.hex_start..contents.hex_end].copy_from_slice(padded_hex.as_bytes());
    Ok(())
}

/// /Contents <...> の hex 文字列開始位置を見つける
fn find_contents_hex_start(data: &[u8], search_from: usize) -> Option<usize> {
    let needle = b"/Contents <";
    let slice = &data[search_from..];
    let pos = slice.windows(needle.len()).position(|w| w == needle)?;
    Some(search_from + pos + needle.len())
}

// ---------------------------------------------------------------------------
// PDF 署名検証
// ---------------------------------------------------------------------------

pub fn pdf_verify(input: &str) -> Result<(), Error> {
    log::info!("Loading signed PDF from {}", input);
    let data = fs::read(input)?;

    // PDF 内のすべての /Type /Sig 辞書を取得する。
    // PAdES (ETSI EN 319 142) は複数署名の場合「すべての署名を検証する」ことを
    // 要求する。最初の署名だけで停止すると、後続の (改ざん・失効後・偽造) 署名が
    // 無検証で素通りする。
    let sigs = find_all_signature_dicts(&data);
    if sigs.is_empty() {
        return Err(Error::from("PDF内に署名辞書が見つかりません"));
    }
    log::info!(
        "Found {} signature dictionary(ies); validating each",
        sigs.len()
    );

    log::info!("Building certificate store for PDF signature verification");
    let roots = verify::build_sign_verifier()?;
    verify::log_sign_trust_anchors(&roots)?;

    let n = sigs.len();
    for (i, (byte_range, contents_hex, angle_start, angle_end)) in sigs.iter().enumerate() {
        let label = format!("署名 #{}/{}", i + 1, n);
        let is_last = i + 1 == n;
        verify_one_signature(
            &data,
            byte_range,
            contents_hex,
            *angle_start,
            *angle_end,
            is_last,
            &roots,
        )
        .map_err(|e| Error::with_source(format!("{} の検証に失敗しました", label), e))?;
        log::info!("{} verified successfully", label);
    }

    println!("Verification successful");
    Ok(())
}

/// 1 つの署名辞書を検証する (PKCS#7 パース、ByteRange からのハッシュ計算、CMS 検証)。
///
/// `is_last_signature` が true のときは、ByteRange が文書末尾まで到達することを
/// 追加で要求する (PAdES Incremental Update Attack 防御)。複数署名 PDF では
/// 中間署名の ByteRange は自然に文書途中で終わる (後続の incremental update が
/// あるため) ので、末尾検査は最後の署名のみに適用する。
fn verify_one_signature(
    data: &[u8],
    byte_range: &str,
    contents_hex: &str,
    contents_angle_start: usize,
    contents_angle_end: usize,
    is_last_signature: bool,
    roots: &[crate::ta::EmbeddedTrustAnchor],
) -> Result<(), Error> {
    // ByteRange を解析
    let ranges = parse_byte_range(byte_range)
        .ok_or_else(|| Error::from("ByteRange の解析に失敗しました"))?;
    log::debug!("PDF ByteRange: {:?}", ranges);
    let ranges_arr: [usize; 4] = [ranges[0], ranges[1], ranges[2], ranges[3]];

    // PAdES 必須: 全署名共通の局所不変条件 (off1==0, end1==<位置, off2==>位置直後)
    verify_byte_range_local_invariants(&ranges_arr, contents_angle_start, contents_angle_end)?;
    // 最後の署名は文書末尾までカバーしていなければならない (末尾追記改ざん防御)
    if is_last_signature {
        verify_byte_range_reaches_end(data, &ranges_arr)?;
    }
    log::debug!("ByteRange invariants verified (is_last={})", is_last_signature);

    let (off1, len1, off2, len2) = (ranges_arr[0], ranges_arr[1], ranges_arr[2], ranges_arr[3]);

    // ByteRange の境界が data の範囲内に収まっているか確認する
    // (局所不変条件で off1==0, off2==angle_end は既に保証されているが、
    // 中間署名の len2 が data.len() を越えるケースを念のため拒否)
    let end1 = off1
        .checked_add(len1)
        .ok_or_else(|| Error::from("ByteRange[0]+ByteRange[1] が usize オーバーフロー"))?;
    let end2 = off2
        .checked_add(len2)
        .ok_or_else(|| Error::from("ByteRange[2]+ByteRange[3] が usize オーバーフロー"))?;
    if end1 > data.len() || end2 > data.len() {
        return Err(Error::from(format!(
            "ByteRange が data 末尾 ({}) を超えています (end1={}, end2={})",
            data.len(),
            end1,
            end2
        )));
    }

    let range1 = &data[off1..end1];
    let range2 = &data[off2..end2];

    // 検証用データ（ByteRange 区間を結合）
    let mut verify_data = Vec::new();
    verify_data.extend_from_slice(range1);
    verify_data.extend_from_slice(range2);

    log::info!("Recomputing detached PDF content digest");
    let content_hash = Sha256::new()
        .chain_update(range1)
        .chain_update(range2)
        .finalize();
    log::trace!(
        "PDF detached content SHA-256 digest: {}",
        utils::hex_encode_upper(content_hash.as_ref())
    );

    // /Contents を hex デコード（DER長を読み取ってパディングを正確に除去）
    let cms_der = extract_der_from_padded_hex(contents_hex)?;

    let ci = ContentInfo::from_der(&cms_der)
        .map_err(|e| Error::with_source("ContentInfo の DER パースに失敗しました", e))?;
    let content_der = ci
        .content
        .to_der()
        .map_err(|e| Error::with_source("content の DER エンコードに失敗しました", e))?;
    let signed_data = SignedData::from_der(&content_der)
        .map_err(|e| Error::with_source("SignedData の DER パースに失敗しました", e))?;
    log::info!("Parsed embedded PKCS#7 signature");
    verify::log_pkcs7_signers(&signed_data)?;

    verify::verify_signer_certificates(&signed_data, roots)?;

    log::info!("Checking PDF content digest, CMS signature, and signer certificate chain");
    verify::verify_cms_signature(&signed_data, Some(&verify_data), roots)
}

/// パディングされた hex 文字列から正しい DER データを抽出する。
///
/// `/Contents <…>` の hex は固定長のプレースホルダに padding `0` を詰めた
/// 形になっているため、DER 先頭の長さフィールドから本体サイズを読み取って
/// 必要なバイト数だけ切り出す。
///
/// 攻撃者が制御する `/Contents` が短すぎる・長さフィールドが不正な値を
/// 指している、といった場合に panic せず明示的にエラーを返す。
fn extract_der_from_padded_hex(hex_str: &str) -> Result<Vec<u8>, Error> {
    // 先頭最大 6 バイト分の長さフィールドだけを先に読み取る (短形式 1B / 長形式 1+nB)
    let bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .take(6)
        .filter_map(|i| {
            hex_str
                .get(i..i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();

    if bytes.len() < 2 {
        return Err(Error::from(
            "DER データが短すぎます: 最低 2 バイトが必要です",
        ));
    }

    let (header_len, content_len) = if bytes[1] < 0x80 {
        (2, bytes[1] as usize)
    } else {
        let num_bytes = (bytes[1] & 0x7f) as usize;
        // 長形式長で必要なバイト数が、先読みした 6 バイトに収まらないケースは
        // 不正入力として明示的に拒否する (旧実装は ここで out-of-bounds panic していた)。
        if num_bytes == 0 {
            return Err(Error::from(
                "DER 長形式の長さフィールドが 0 バイトを指しています",
            ));
        }
        if 2 + num_bytes > bytes.len() {
            return Err(Error::from(format!(
                "DER 長形式の長さフィールド ({} バイト) が読み取り可能サイズを超えています",
                num_bytes
            )));
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | bytes[2 + i] as usize;
        }
        (2 + num_bytes, len)
    };

    let total = header_len
        .checked_add(content_len)
        .ok_or_else(|| Error::from("DER 全長が usize オーバーフロー"))?;
    let hex_len = total
        .checked_mul(2)
        .ok_or_else(|| Error::from("DER 全長 * 2 が usize オーバーフロー"))?;
    if hex_len > hex_str.len() {
        return Err(Error::from(format!(
            "DER の宣言長 ({} バイト) が hex 文字列長 ({} hex chars) を超えています",
            total,
            hex_str.len()
        )));
    }
    utils::hex_decode(&hex_str[..hex_len])
        .map_err(|e| Error::with_source("DER hex デコードに失敗しました", e))
}

/// PDF 内のすべての /Type /Sig 辞書を文書順に返す。
///
/// 各エントリは `(byte_range, contents_hex, contents_angle_start, contents_angle_end)` の 4-tuple。
/// - `byte_range`: `[a b c d]` 形式の文字列
/// - `contents_hex`: `/Contents <…>` の hex 文字列本体
/// - `contents_angle_start`: `<` のバイト位置
/// - `contents_angle_end`: `>` の直後のバイト位置 (排他的)
///
/// PAdES では複数署名 PDF (例: 当事者 A の署名 → 後で当事者 B が追加署名) が
/// 認められており、検証側はすべての署名を順に検証する必要がある (GHSA-g258-q5gf-7hvx)。
/// `<` `>` 位置は ByteRange のカバレッジ検査 (GHSA-rxpx-26p9-4xvr) に必要。
fn find_all_signature_dicts(data: &[u8]) -> Vec<(String, String, usize, usize)> {
    let mut out = Vec::new();
    let needle = b"/Type /Sig";
    let mut search_from = 0;
    while search_from < data.len() {
        let pos = match find_bytes(data, needle, search_from) {
            Some(p) => p,
            None => break,
        };

        let dict_start = match find_bytes_rev(data, b"<<", pos) {
            Some(s) => s,
            None => {
                search_from = pos + needle.len();
                continue;
            }
        };
        let dict_end = match find_nesting_dict_end(data, dict_start) {
            Some(e) => e,
            None => {
                search_from = pos + needle.len();
                continue;
            }
        };
        let dict_text = String::from_utf8_lossy(&data[dict_start..dict_end]);

        if let Some(byte_range) = extract_array_value(&dict_text, "/ByteRange")
            && let Some((contents, angle_start, angle_end)) =
                extract_hex_string_from(data, dict_start)
        {
            out.push((byte_range, contents, angle_start, angle_end));
        }

        search_from = pos + needle.len();
    }
    out
}

/// PAdES (ETSI EN 319 142) / PDF 2.0 (ISO 32000-2 §12.8) で要求される
/// ByteRange の局所不変条件を検証する。
///
/// すなわち、ByteRange `[off1, len1, off2, len2]` が指定する 2 区間が
/// - 文書先頭から始まる (`off1 == 0`)
/// - `/Contents <…>` プレースホルダの `<` 直前で終わる (`off1 + len1 == angle_start`)
/// - プレースホルダの `>` 直後から始まる (`off2 == angle_end`)
///
/// ことを確認する。複数署名 PDF の中間署名でも成立する不変条件のみを扱い、
/// 「文書末尾まで到達するか」は別関数 [`verify_byte_range_reaches_end`] で扱う
/// (中間署名は後続の incremental update があるため、自然に文書途中で終わる)。
fn verify_byte_range_local_invariants(
    ranges: &[usize; 4],
    angle_start: usize,
    angle_end: usize,
) -> Result<(), Error> {
    let [off1, len1, off2, _len2] = *ranges;

    if off1 != 0 {
        return Err(Error::from(format!(
            "ByteRange[0] が 0 ではありません ({}); 文書先頭が署名対象に含まれていません",
            off1
        )));
    }
    let end1 = off1.checked_add(len1).ok_or_else(|| {
        Error::from("ByteRange[0]+ByteRange[1] が usize オーバーフローしました")
    })?;
    if end1 != angle_start {
        return Err(Error::from(format!(
            "ByteRange 第 1 区間の終端 ({}) が /Contents の '<' 位置 ({}) と一致しません",
            end1, angle_start
        )));
    }
    if off2 != angle_end {
        return Err(Error::from(format!(
            "ByteRange 第 2 区間の開始 ({}) が /Contents の '>' 直後 ({}) と一致しません",
            off2, angle_end
        )));
    }
    Ok(())
}

/// ByteRange の第 2 区間が **文書末尾まで** 到達していることを検証する。
///
/// このチェックを欠くと、攻撃者は正規署名済み PDF の末尾に Incremental Update
/// (xref + 改ざん /Catalog + 新 startxref) を追記するだけで、署名検証を
/// 通過させたまま PDF ビューア上では改ざん後の内容を表示させることができる
/// (Incremental Update Attack / "Incremental Saving Attack",
/// Mladenov et al., "1 Trillion Dollar Refund — How to Spoof PDF Signatures",
/// CCS'19)。
///
/// 複数署名 PDF では **最後の署名のみ** に適用すること。中間署名は後続の
/// incremental update が追記されているため、自然に文書途中で終わる。
fn verify_byte_range_reaches_end(data: &[u8], ranges: &[usize; 4]) -> Result<(), Error> {
    let [_off1, _len1, off2, len2] = *ranges;
    let end2 = off2.checked_add(len2).ok_or_else(|| {
        Error::from("ByteRange[2]+ByteRange[3] が usize オーバーフローしました")
    })?;
    if end2 != data.len() {
        return Err(Error::from(format!(
            "ByteRange 第 2 区間の終端 ({}) が文書末尾 ({}) と一致しません \
             (Incremental Update による改ざんの可能性)",
            end2,
            data.len()
        )));
    }
    Ok(())
}

/// ネスト対応の辞書終端 `>>` を検索
fn find_nesting_dict_end(data: &[u8], dict_start: usize) -> Option<usize> {
    let mut depth = 0;
    let mut i = dict_start;
    while i < data.len().saturating_sub(1) {
        if data[i] == b'<' && data[i + 1] == b'<' {
            depth += 1;
            i += 2;
        } else if data[i] == b'>' && data[i + 1] == b'>' {
            depth -= 1;
            if depth == 0 {
                return Some(i + 2);
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

/// 配列値 `[...]` を抽出
fn extract_array_value(text: &str, key: &str) -> Option<String> {
    let pos = text.find(key)?;
    let after = &text[pos + key.len()..];
    let start = after.find('[')?;
    let end = after.find(']')?;
    Some(after[start..=end].to_string())
}

/// /Contents <hex> の hex 文字列と、`<` `>` のバイト位置を抽出する。
///
/// 返値の `angle_start` は `<` のバイト位置 (= hex 開始の 1 つ手前)、
/// `angle_end` は `>` の **直後** のバイト位置 (= 排他的終端)。
fn extract_hex_string_from(
    data: &[u8],
    search_from: usize,
) -> Option<(String, usize, usize)> {
    let needle = b"/Contents <";
    let pos = find_bytes(data, needle, search_from)?;
    let angle_start = pos + needle.len() - 1; // `<` の位置
    let hex_start = angle_start + 1;
    let end = data[hex_start..].iter().position(|&b| b == b'>')?;
    let hex_bytes = &data[hex_start..hex_start + end];
    let angle_end = hex_start + end + 1; // `>` の直後
    Some((
        String::from_utf8_lossy(hex_bytes).to_string(),
        angle_start,
        angle_end,
    ))
}

/// ByteRange 配列 `[a b c d]` を解析
fn parse_byte_range(s: &str) -> Option<Vec<usize>> {
    let inner = s.trim_start_matches('[').trim_end_matches(']');
    let nums: Vec<usize> = inner
        .split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect();
    if nums.len() == 4 { Some(nums) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- get_xref_dict_text: ネストされた辞書を持つ xref stream ---

    #[test]
    fn test_xref_stream_nested_dict() {
        // DecodeParms にネストされた << >> を含む xref stream
        let data = b"6725 0 obj\r<</DecodeParms<</Columns 5/Predictor 12>>/Filter/FlateDecode/Root 42 0 R/Size 100/Type/XRef>>stream\r\nbinary";
        let dict = get_xref_dict_text(data, 0).unwrap();
        assert!(dict.contains("/Root 42 0 R"), "dict = {}", dict);
        assert!(dict.contains("/Size 100"), "dict = {}", dict);
    }

    #[test]
    fn test_xref_stream_nested_dict_root_ref() {
        let data = b"1 0 obj\r<</DecodeParms<</Columns 5/Predictor 12>>/Root 99 0 R/Size 200/Type/XRef>>stream";
        assert_eq!(find_root_ref(data, 0), Some(99));
    }

    #[test]
    fn test_xref_stream_no_nesting() {
        let data = b"1 0 obj <</Root 7 0 R/Size 50/Type/XRef>>stream";
        let dict = get_xref_dict_text(data, 0).unwrap();
        assert!(dict.contains("/Root 7 0 R"));
    }

    // --- find_object_content: 改行区切りのオブジェクトヘッダー ---

    #[test]
    fn test_find_object_content_newline_separated() {
        // "4\n0\nobj\n<<...>>\nendobj" 形式
        let data = b"4\n0\nobj\n<< /Type /Catalog /Pages 1 0 R >>\nendobj\n";
        let content = find_object_content(data, 4).unwrap();
        assert!(content.contains("/Type /Catalog"), "content = {}", content);
    }

    #[test]
    fn test_find_object_content_cr_lf_separated() {
        let data = b"10\r\n0\r\nobj\r\n<< /Type /Catalog >>\r\nendobj\r\n";
        let content = find_object_content(data, 10).unwrap();
        assert!(content.contains("/Type /Catalog"), "content = {}", content);
    }

    #[test]
    fn test_find_object_content_space_separated() {
        let data = b"7 0 obj\n<< /Type /Page >>\nendobj\n";
        let content = find_object_content(data, 7).unwrap();
        assert!(content.contains("/Type /Page"), "content = {}", content);
    }

    #[test]
    fn test_find_object_content_not_found() {
        let data = b"5 0 obj\n<< /Type /Page >>\nendobj\n";
        assert!(find_object_content(data, 99).is_none());
    }

    // --- traditional trailer ---

    #[test]
    fn test_traditional_trailer_newline_values() {
        // a.pdf のような改行区切りの trailer
        let data =
            b"xref\n0 10\ntrailer\n<<\n/Size\n174\n/Root\n4\n0\nR\n>>\nstartxref\n0\n%%EOF\n";
        let dict = get_xref_dict_text(data, 0).unwrap();
        assert!(dict.contains("/Root"), "dict = {}", dict);
        assert_eq!(find_root_ref(data, 0), Some(4));
    }

    // ---------------------------------------------------------------------
    // PAdES ByteRange 局所不変条件 + 末尾到達検査 (Incremental Update Attack 防御)
    // ---------------------------------------------------------------------

    /// テスト用に、`/Type /Sig` 辞書を持つ buffer と、その正しい
    /// ByteRange / `<` `>` 位置を返す。署名そのものは含めない (本検査の対象は
    /// ByteRange の構造要件であり、CMS 検証は別経路で行うため)。
    fn build_test_signed_buffer() -> (Vec<u8>, [usize; 4], usize, usize) {
        let head: Vec<u8> = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\nfiller\n".to_vec();
        let contents_hex = "00".repeat(64); // 128 hex chars (= 64 bytes)
        let br_placeholder = format!("[{:<10} {:<10} {:<10} {:<10}]", "X", "Y", "Z", "W");
        let sig_prefix = format!(
            "1 0 obj\n<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n/ByteRange {}\n/Contents <",
            br_placeholder
        );
        let sig_suffix = b">\n>>\nendobj\n";
        let trailer = b"\nxref\n0 2\n0000000000 65535 f \n0000000016 00000 n \ntrailer\n<<\n/Size 2\n/Root 1 0 R\n>>\nstartxref\n16\n%%EOF\n";

        let angle_start = head.len() + sig_prefix.len() - 1;
        let angle_end = angle_start + 1 + contents_hex.len() + 1;

        let mut buf = Vec::new();
        buf.extend_from_slice(&head);
        buf.extend_from_slice(sig_prefix.as_bytes());
        buf.extend_from_slice(contents_hex.as_bytes());
        buf.extend_from_slice(sig_suffix);
        buf.extend_from_slice(trailer);

        let signed_len = buf.len();
        let br_actual = format!(
            "[{:<10} {:<10} {:<10} {:<10}]",
            0,
            angle_start,
            angle_end,
            signed_len - angle_end
        );
        let placeholder_bytes = br_placeholder.as_bytes();
        let br_pos = buf
            .windows(placeholder_bytes.len())
            .position(|w| w == placeholder_bytes)
            .unwrap();
        buf[br_pos..br_pos + placeholder_bytes.len()].copy_from_slice(br_actual.as_bytes());

        let ranges = [0, angle_start, angle_end, signed_len - angle_end];
        (buf, ranges, angle_start, angle_end)
    }

    #[test]
    fn test_byterange_coverage_accepts_correctly_signed_buffer() {
        let (buf, ranges, angle_start, angle_end) = build_test_signed_buffer();
        // 正しく ByteRange を書き出した直後の buffer は受理される。
        verify_byte_range_local_invariants(&ranges, angle_start, angle_end)
            .expect("局所不変条件: 正規ファイルは受理されるべき");
        verify_byte_range_reaches_end(&buf, &ranges)
            .expect("末尾到達: 正規ファイルは受理されるべき");
    }

    #[test]
    fn test_byterange_coverage_rejects_appended_incremental_update() {
        // 攻撃者が末尾に Incremental Update を追記したケース。
        // ByteRange は元の signed_len 時点のまま、buf だけ伸びる。
        let (mut buf, ranges, _angle_start, _angle_end) = build_test_signed_buffer();
        buf.extend_from_slice(&b"\n%%-INJECTED-INCREMENTAL-UPDATE-".repeat(100));
        let err = verify_byte_range_reaches_end(&buf, &ranges)
            .expect_err("末尾追記された buffer は拒否されるべき");
        let msg = err.to_string();
        assert!(
            msg.contains("文書末尾"),
            "想定外のエラーメッセージ: {}",
            msg
        );
    }

    #[test]
    fn test_byterange_coverage_rejects_off1_nonzero() {
        let (buf, _ranges, angle_start, angle_end) = build_test_signed_buffer();
        // ByteRange[0] を 0 ではない値に変える (= 文書先頭が署名対象外)
        let bad = [1, angle_start - 1, angle_end, buf.len() - angle_end];
        let err = verify_byte_range_local_invariants(&bad, angle_start, angle_end)
            .expect_err("ByteRange[0] != 0 は拒否されるべき");
        assert!(err.to_string().contains("ByteRange[0]"), "{}", err);
    }

    #[test]
    fn test_byterange_coverage_rejects_short_first_range() {
        let (_buf, _ranges, angle_start, angle_end) = build_test_signed_buffer();
        // 第 1 区間が `<` の手前で終わらない
        let bad = [0, angle_start - 5, angle_end, 0];
        let err = verify_byte_range_local_invariants(&bad, angle_start, angle_end)
            .expect_err("第 1 区間が短いケースは拒否されるべき");
        assert!(err.to_string().contains("第 1 区間"), "{}", err);
    }

    #[test]
    fn test_byterange_coverage_rejects_wrong_off2() {
        let (_buf, _ranges, angle_start, angle_end) = build_test_signed_buffer();
        // 第 2 区間が `>` の直後ではないところから始まる
        let bad = [0, angle_start, angle_end + 3, 0];
        let err = verify_byte_range_local_invariants(&bad, angle_start, angle_end)
            .expect_err("第 2 区間の開始位置が誤っているケースは拒否されるべき");
        assert!(err.to_string().contains("第 2 区間"), "{}", err);
    }

    #[test]
    fn test_byterange_coverage_end_to_end_via_find_all_signature_dicts() {
        // find_all_signature_dicts が返す angle_start / angle_end と
        // verify_byte_range_reaches_end を組み合わせた end-to-end テスト。
        // 末尾追記された buffer に対して、ByteRange パース後の検査で確実に
        // エラーになることを確認する (pdf_verify の検証経路と同じ流れ)。
        let (mut buf, _ranges, _, _) = build_test_signed_buffer();
        buf.extend_from_slice(b"\n%%- attacker payload appended after signing -\n");

        let sigs = find_all_signature_dicts(&buf);
        assert_eq!(sigs.len(), 1, "single sig expected");
        let (br_str, _contents, _angle_start, _angle_end) = &sigs[0];
        let parsed = parse_byte_range(br_str).expect("ByteRange parsed");
        let arr = [parsed[0], parsed[1], parsed[2], parsed[3]];

        let err = verify_byte_range_reaches_end(&buf, &arr)
            .expect_err("末尾追記された buffer は ByteRange カバー検査で拒否されるべき");
        assert!(err.to_string().contains("文書末尾"), "{}", err);
    }

    // ---------------------------------------------------------------------
    // find_all_signature_dicts: 複数署名検出 (GHSA-g258-q5gf-7hvx 修正の中核)
    // ---------------------------------------------------------------------

    #[test]
    fn test_find_all_signature_dicts_returns_empty_for_no_sig() {
        let data = b"%PDF-1.7\nfiller content\n%%EOF\n";
        let sigs = find_all_signature_dicts(data);
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_find_all_signature_dicts_returns_one_for_single_sig() {
        let data = b"%PDF-1.7\nfiller\n\
                     1 0 obj\n<<\n/Type /Sig\n/ByteRange [0 10 30 5]\n/Contents <00>\n>>\nendobj\n";
        let sigs = find_all_signature_dicts(data);
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].0.contains("0"), "byte_range = {}", sigs[0].0);
    }

    #[test]
    fn test_find_all_signature_dicts_returns_two_for_multi_sig() {
        // 2 つの /Type /Sig 辞書 (incremental update で sig#2 が後から追加されたケース)
        let data = b"%PDF-1.7\nfiller\n\
                     1 0 obj\n<<\n/Type /Sig\n/ByteRange [0 10 30 5]\n/Contents <00>\n>>\nendobj\n\
                     %% incremental update follows %%\n\
                     2 0 obj\n<<\n/Type /Sig\n/ByteRange [0 0 0 0]\n/Contents <DEAD>\n>>\nendobj\n";
        let sigs = find_all_signature_dicts(data);
        assert_eq!(
            sigs.len(),
            2,
            "two /Type /Sig dicts should be detected, found {:?}",
            sigs
        );
    }

    // ---------------------------------------------------------------------
    // extract_der_from_padded_hex: 攻撃者制御 /Contents で panic しないこと
    // (GHSA-g258-q5gf-7hvx 攻撃シナリオで踏まれる入力。Result 化により明示エラー)
    // ---------------------------------------------------------------------

    #[test]
    fn test_extract_der_from_padded_hex_rejects_too_short() {
        // 1 バイト分しかない hex (最低 2 バイト必要) はエラー
        let result = extract_der_from_padded_hex("30");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("短すぎ"),
            "想定外のエラー"
        );
    }

    #[test]
    fn test_extract_der_from_padded_hex_rejects_long_form_overflow() {
        // 旧実装が panic したケース: bytes[1] = 0xAD = long-form 45 バイト
        // → bytes[2 + i] が out-of-bounds → panic していた。
        // Result 化後は明示エラーとして拒否する。
        let result = extract_der_from_padded_hex("DEADBEEFCAFEBABE0123456789ABCDEFFEEDFACE");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("長形式") || msg.contains("読み取り可能"),
            "想定外のエラー: {}",
            msg
        );
    }

    #[test]
    fn test_extract_der_from_padded_hex_rejects_declared_length_too_large() {
        // 短形式: bytes[1] = 0x7F = 127 バイト宣言、しかし hex は短い
        let result = extract_der_from_padded_hex("307F00");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("超え"), "想定外のエラー: {}", msg);
    }

    #[test]
    fn test_extract_der_from_padded_hex_short_form_ok() {
        // 正常形: SEQUENCE { INTEGER 0 } を表す `30 03 02 01 00`
        let result = extract_der_from_padded_hex("3003020100");
        assert!(result.is_ok());
        let der = result.unwrap();
        assert_eq!(der, vec![0x30, 0x03, 0x02, 0x01, 0x00]);
    }

    // ---------------------------------------------------------------------
    // 統合: 複数署名 PDF (sig#1 valid, sig#2 garbage) → sig#2 検証で Err
    // (GHSA-g258-q5gf-7hvx 攻撃シナリオの回帰テスト)
    // ---------------------------------------------------------------------

    /// テスト用: sig#1 は本物の CMS 検出署名、sig#2 はゴミ /Contents (CMS パース不可)
    /// を持つ multi-sig buffer を構築。試験用 CA を信頼アンカーとして渡す前提。
    fn build_multi_sig_buffer_for_test() -> (Vec<u8>, Vec<crate::ta::EmbeddedTrustAnchor>, Vec<u8>) {
        use crate::pkcs7;
        use crate::ta::EmbeddedTrustAnchor;
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;
        use sha2::{Digest, Sha256};
        use x509_cert::Certificate;

        let cert_der = include_bytes!("../tests/fixtures/sign_cert.der");
        let ca_der = include_bytes!("../tests/fixtures/sign_ca_cert.der");
        let sign_key_pem = include_bytes!("../tests/fixtures/sign_key.pem");
        let priv_key =
            RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(sign_key_pem).unwrap()).unwrap();

        let raw_pkcs1v15_sign = |data: &[u8]| -> Vec<u8> {
            use rsa::BigUint;
            use rsa::hazmat::rsa_decrypt_and_check;
            use rsa::traits::PublicKeyParts;
            let key_size = priv_key.size();
            let ps_len = key_size - data.len() - 3;
            let mut em = vec![0x00u8, 0x01];
            em.extend(std::iter::repeat_n(0xffu8, ps_len));
            em.push(0x00);
            em.extend_from_slice(data);
            let m = BigUint::from_bytes_be(&em);
            let c =
                rsa_decrypt_and_check(&priv_key, None::<&mut rsa::rand_core::OsRng>, &m).unwrap();
            let mut sig = c.to_bytes_be();
            while sig.len() < key_size {
                sig.insert(0, 0u8);
            }
            sig
        };

        // sig #1: 正規 CMS detached 署名を埋め込む
        let placeholder_hex = "0".repeat(SIG_CONTENTS_SIZE * 2);
        let head: Vec<u8> = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\nfiller\n".to_vec();
        let sig1_prefix = format!(
            "1 0 obj\n<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n/ByteRange [{:<10} {:<10} {:<10} {:<10}]\n/Contents <",
            "X", "Y", "Z", "W"
        );
        let sig1_suffix = b">\n>>\nendobj\n";
        let mid_trailer = b"\nxref\n0 2\n0000000000 65535 f \n0000000016 00000 n \ntrailer\n<<\n/Size 2\n/Root 1 0 R\n>>\nstartxref\n16\n%%EOF\n";

        let sig1_angle_start = head.len() + sig1_prefix.len() - 1;
        let sig1_angle_end = sig1_angle_start + 1 + placeholder_hex.len() + 1;

        let mut buf = Vec::new();
        buf.extend_from_slice(&head);
        buf.extend_from_slice(sig1_prefix.as_bytes());
        buf.extend_from_slice(placeholder_hex.as_bytes());
        buf.extend_from_slice(sig1_suffix);
        buf.extend_from_slice(mid_trailer);

        let sig1_signed_len = buf.len();
        let sig1_br = format!(
            "[{:<10} {:<10} {:<10} {:<10}]",
            0,
            sig1_angle_start,
            sig1_angle_end,
            sig1_signed_len - sig1_angle_end
        );
        let placeholder_br = format!("[{:<10} {:<10} {:<10} {:<10}]", "X", "Y", "Z", "W");
        let placeholder_bytes = placeholder_br.as_bytes();
        let br_pos = buf
            .windows(placeholder_bytes.len())
            .position(|w| w == placeholder_bytes)
            .unwrap();
        buf[br_pos..br_pos + placeholder_bytes.len()].copy_from_slice(sig1_br.as_bytes());

        let content_hash = Sha256::new()
            .chain_update(&buf[0..sig1_angle_start])
            .chain_update(&buf[sig1_angle_end..])
            .finalize()
            .to_vec();
        let alg = pkcs7::HashAlgorithm::Sha256;
        let (attrs, attrs_digest) = pkcs7::prepare_signing_with_hash(&content_hash, alg);
        let digest_info = pkcs7::build_digest_info(alg, &attrs_digest);
        let signature = raw_pkcs1v15_sign(&digest_info);
        let pkcs7_der = pkcs7::build_signed_data_detached(cert_der, &signature, alg, &attrs);
        let sig_hex = crate::utils::hex_encode(&pkcs7_der);
        let padded_hex = format!("{:0<width$}", sig_hex, width = SIG_CONTENTS_SIZE * 2);
        buf[sig1_angle_start + 1..sig1_angle_end - 1].copy_from_slice(padded_hex.as_bytes());

        // sig #2: incremental update 風に追記したゴミ署名。
        // /Contents は短形式 DER として有効 (extract_der_from_padded_hex は通る) だが、
        // 中身は PKCS#7 ContentInfo として不正なため CMS 検証で必ず Err になる。
        let sig2_garbage = b"\n%%-malicious incremental update follows --\n\
                             3 0 obj\n\
                             <<\n\
                             /Type /Sig\n\
                             /Filter /Adobe.PPKLite\n\
                             /SubFilter /adbe.pkcs7.detached\n\
                             /ByteRange [0 0 0 0]\n\
                             /Contents <3003020100>\n\
                             /Reason (Malicious second signature, never validated by buggy verifiers)\n\
                             >>\n\
                             endobj\n";
        buf.extend_from_slice(sig2_garbage);

        let ca_cert = Certificate::from_der(ca_der).unwrap();
        let test_roots = vec![EmbeddedTrustAnchor {
            name: "test_sign_ca",
            cert: ca_cert,
        }];

        (buf, test_roots, ca_der.to_vec())
    }

    #[test]
    fn test_multi_sig_pdf_with_garbage_second_signature_is_rejected() {
        let (buf, roots, _) = build_multi_sig_buffer_for_test();

        // 前提: 2 つの /Type /Sig 辞書が見つかること
        let sigs = find_all_signature_dicts(&buf);
        assert_eq!(
            sigs.len(),
            2,
            "buffer must contain 2 signatures, found {}",
            sigs.len()
        );

        // sig#1 (正規 CMS) は単独 (is_last=false 相当) では受理される。
        // 中間署名は文書末尾まで届かないので is_last=false で検証する。
        let (br1, hex1, as1, ae1) = &sigs[0];
        let res1 = verify_one_signature(&buf, br1, hex1, *as1, *ae1, false, &roots);
        assert!(res1.is_ok(), "sig#1 should verify on its own: {:?}", res1);

        // sig#2 (ゴミ /Contents) は CMS パースで Err になる
        let (br2, hex2, as2, ae2) = &sigs[1];
        let res2 = verify_one_signature(&buf, br2, hex2, *as2, *ae2, true, &roots);
        assert!(
            res2.is_err(),
            "sig#2 must fail (garbage /Contents) but got Ok"
        );

        // pdf_verify が「すべての署名を検証する」設計に従うなら、
        // 2 つを順に検証 → sig#2 で Err → 全体として Err になる。
        // (旧実装は sig#1 だけで止まり、sig#2 は素通りしていた)
    }
}
