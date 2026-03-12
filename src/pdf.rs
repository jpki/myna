/// PDF電子署名(PAdES/PKCS#7 detached)の実装
///
/// マイナンバーカードのJPKI署名用鍵でPDFにインクリメンタル追記で電子署名を埋め込む。
use crate::jpki::{DigestAlgorithm, PdfSignArgs, PdfSubcommand, PdfVerifyArgs};
use crate::pkcs7;
use crate::reader::MynaReader;
use crate::utils;
use flate2::read::ZlibDecoder;
use openssl::hash::MessageDigest;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::X509;
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

    loop {
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
                if parts.len() == 2 {
                    if let (Ok(start), Ok(count)) =
                        (parts[0].parse::<usize>(), parts[1].parse::<usize>())
                    {
                        let end = start + count;
                        if end > max_id {
                            max_id = end;
                        }
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
                if let Ok(id) = obj_id_str.parse::<usize>() {
                    if id + 1 > max_id {
                        max_id = id + 1;
                    }
                }
                if let Some(size) = extract_int_value(text, "/Size") {
                    if size > max_id {
                        max_id = size;
                    }
                }
            }
        }

        // /Prev を探す
        let dict = get_xref_dict_text(data, offset);
        if let Some(ref text) = dict {
            if let Some(prev) = extract_int_value(text, "/Prev") {
                offset = prev;
                continue;
            }
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

    // バイナリセーフに "trailer" を検索
    if let Some(pos) = slice.windows(7).position(|w| w == b"trailer") {
        let trailer_slice = &slice[pos..];
        let end = trailer_slice
            .windows(2)
            .position(|w| w == b">>")
            .map(|p| p + 2)
            .unwrap_or(std::cmp::min(trailer_slice.len(), 1024));
        return Some(String::from_utf8_lossy(&trailer_slice[..end]).to_string());
    }

    // xref stream: "N 0 obj\n<< ... >>\nstream" の辞書部分を取得
    let dict_start = slice.windows(2).position(|w| w == b"<<")?;
    let inner = &slice[dict_start + 2..];
    let dict_end_rel = inner.windows(2).position(|w| w == b">>")?;
    let dict_end = dict_start + 2 + dict_end_rel + 2;
    Some(String::from_utf8_lossy(&slice[dict_start..dict_end]).to_string())
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
fn find_object_content(data: &[u8], obj_id: usize) -> Option<String> {
    let needle = format!("{} 0 obj", obj_id);
    let needle_bytes = needle.as_bytes();
    for i in 0..data.len().saturating_sub(needle_bytes.len()) {
        if &data[i..i + needle_bytes.len()] == needle_bytes {
            if i == 0 || data[i - 1] == b'\n' || data[i - 1] == b'\r' {
                let start = i + needle_bytes.len();
                let rest = &data[start..];
                if let Some(end_pos) = rest.windows(6).position(|w| w == b"endobj") {
                    let content = &data[start..start + end_pos];
                    return Some(String::from_utf8_lossy(content).to_string());
                }
            }
        }
    }
    None
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

pub fn pdf_sign(args: &PdfSignArgs) {
    let password = {
        let pass = utils::prompt_input("署名用パスワード(6-16桁): ", &args.password);
        let pass = pass.to_uppercase();
        utils::validate_jpki_sign_password(&pass).expect("パスワードが不正です");
        pass
    };

    // 入力PDFを読み込み
    let original = fs::read(&args.input).expect("入力PDFファイルを読み込めませんでした");

    // カードに接続して証明書を取得
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("001b").unwrap();
    reader
        .verify_pin(&password)
        .expect("パスワード認証に失敗しました");
    reader.select_ef("0001").unwrap();
    let cert_der = reader.read_binary_all();
    let cert = X509::from_der(&cert_der).expect("証明書のパースに失敗しました");

    // PDF構造を解析
    let xref_offset = find_startxref(&original).expect("startxref が見つかりません");
    let root_ref = find_root_ref(&original, xref_offset).expect("/Root が見つかりません");
    let trailer_size = find_trailer_size(&original, xref_offset).expect("/Size が見つかりません");
    let info_ref = find_info_ref(&original, xref_offset);
    let max_id = find_max_obj_id(&original, xref_offset);
    let next_id = std::cmp::max(max_id, trailer_size);

    // Root オブジェクトの辞書内容を取得
    let root_dict_text =
        get_object_dict(&original, root_ref).expect("Root カタログオブジェクトが見つかりません");

    // 新オブジェクトIDを割り当て
    let sig_obj_id = next_id;
    let widget_obj_id = next_id + 1;
    let acroform_obj_id = next_id + 2;
    let updated_root_id = root_ref;
    let new_size = next_id + 3;

    // /Contents プレースホルダ (hex文字列)
    let placeholder_hex = "0".repeat(SIG_CONTENTS_SIZE * 2);

    // ByteRange のプレースホルダ（後で上書きするので十分なスペースを確保）
    let byterange_placeholder = format!("[{:<10} {:<10} {:<10} {:<10}]", 0, 0, 0, 0);

    // インクリメンタル追記内容を構築
    let mut append = Vec::new();
    append.push(b'\n');

    // 1. Sig辞書オブジェクト
    let sig_obj_offset = original.len() + append.len();
    let sig_obj = format!(
        "{} 0 obj\n<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n/ByteRange {}\n/Contents <{}>\n/Reason (JPKI Digital Signature)\n>>\nendobj\n",
        sig_obj_id, byterange_placeholder, placeholder_hex
    );
    append.extend(sig_obj.as_bytes());

    // 2. Widget アノテーション
    let widget_obj_offset = original.len() + append.len();
    let widget_obj = format!(
        "{} 0 obj\n<<\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/Rect [0 0 0 0]\n/V {} 0 R\n/T (Sig1)\n/F 132\n>>\nendobj\n",
        widget_obj_id, sig_obj_id
    );
    append.extend(widget_obj.as_bytes());

    // 3. AcroForm オブジェクト
    let acroform_obj_offset = original.len() + append.len();
    let acroform_obj = format!(
        "{} 0 obj\n<<\n/Fields [{} 0 R]\n/SigFlags 3\n>>\nendobj\n",
        acroform_obj_id, widget_obj_id
    );
    append.extend(acroform_obj.as_bytes());

    // 4. 更新 Root オブジェクト（AcroForm追加）
    let updated_root_offset = original.len() + append.len();
    let updated_root_dict = build_updated_root_dict(&root_dict_text, acroform_obj_id);
    let updated_root_obj = format!("{} 0 obj\n{}\nendobj\n", updated_root_id, updated_root_dict);
    append.extend(updated_root_obj.as_bytes());

    // 5. xref テーブル
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

    // 6. trailer
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

    // 出力ファイルに書き出し
    let mut output = original.clone();
    output.extend(&append);

    // ByteRange と /Contents の位置を特定
    let contents_hex_start = find_contents_hex_start(&output, sig_obj_offset)
        .expect("/Contents プレースホルダが見つかりません");
    let contents_hex_end = contents_hex_start + SIG_CONTENTS_SIZE * 2;

    let angle_start = contents_hex_start - 1; // '<' の位置
    let angle_end = contents_hex_end + 1; // '>' の次の位置

    let byte_range = format!(
        "[{:<10} {:<10} {:<10} {:<10}]",
        0,
        angle_start,
        angle_end,
        output.len() - angle_end
    );

    // ByteRange を上書き
    let br_needle = byterange_placeholder.as_bytes();
    let br_pos = output[sig_obj_offset..]
        .windows(br_needle.len())
        .position(|w| w == br_needle)
        .expect("ByteRange プレースホルダが見つかりません")
        + sig_obj_offset;
    output[br_pos..br_pos + byte_range.len()].copy_from_slice(byte_range.as_bytes());

    // 署名対象データのハッシュを計算
    let md = MessageDigest::sha256();
    let range1 = &output[0..angle_start];
    let range2 = &output[angle_end..];
    let mut hasher = openssl::hash::Hasher::new(md).unwrap();
    hasher.update(range1).unwrap();
    hasher.update(range2).unwrap();
    let content_hash = hasher.finish().unwrap().to_vec();

    // PKCS#7 署名を構築
    let (attrs_set, attrs_digest) = pkcs7::prepare_signing_with_hash(&content_hash, md);

    let digest_info = crate::jpki::make_digest_info(&DigestAlgorithm::Sha256, &attrs_digest);
    reader.select_ef("001a").unwrap();
    let signature = reader.signature(&digest_info).expect("署名に失敗しました");

    let pkcs7_der = pkcs7::build_signed_data_detached(&cert, &signature, md, &attrs_set);

    // CMS DER を hex エンコードして /Contents に書き込み
    let sig_hex = hex::encode(&pkcs7_der);
    if sig_hex.len() > SIG_CONTENTS_SIZE * 2 {
        panic!(
            "署名データがプレースホルダサイズを超えています ({} > {})",
            sig_hex.len(),
            SIG_CONTENTS_SIZE * 2
        );
    }

    let padded_hex = format!("{:0<width$}", sig_hex, width = SIG_CONTENTS_SIZE * 2);
    output[contents_hex_start..contents_hex_end].copy_from_slice(padded_hex.as_bytes());

    fs::write(&args.output, &output).expect("出力ファイルへの書き込みに失敗しました");
    println!("PDF署名を保存しました: {}", args.output);
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

pub fn pdf_verify(args: &PdfVerifyArgs) {
    log::info!("Loading signed PDF from {}", args.input);
    let data = fs::read(&args.input).expect("PDFファイルを読み込めませんでした");

    // /Type /Sig を持つ署名辞書を検索
    let (byte_range, contents_hex) =
        find_signature_dict(&data).expect("PDF内に署名辞書が見つかりません");

    // ByteRange を解析
    let ranges = parse_byte_range(&byte_range).expect("ByteRange の解析に失敗しました");
    log::info!("Parsed PDF signature dictionary");
    log::debug!("PDF ByteRange: {:?}", ranges);
    let (off1, len1, off2, len2) = (ranges[0], ranges[1], ranges[2], ranges[3]);

    // 署名対象データのハッシュ
    log::info!("Recomputing detached PDF content digest");
    let md = MessageDigest::sha256();
    let range1 = &data[off1..off1 + len1];
    let range2 = &data[off2..off2 + len2];
    let mut hasher = openssl::hash::Hasher::new(md).unwrap();
    hasher.update(range1).unwrap();
    hasher.update(range2).unwrap();
    let _content_hash = hasher.finish().unwrap();

    // /Contents を hex デコード（DER長を読み取ってパディングを正確に除去）
    let cms_der = extract_der_from_padded_hex(&contents_hex);

    let pkcs7 = Pkcs7::from_der(&cms_der).expect("PKCS7のパースに失敗しました");
    log::info!("Parsed embedded PKCS#7 signature");

    // カードから署名用CA証明書を取得
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("0002").unwrap();
    let ca_cert_der = reader.read_binary_all();
    let ca_cert = X509::from_der(&ca_cert_der).expect("CA証明書のパースに失敗しました");

    // 検証用データ（ByteRange区間を結合）
    let mut verify_data = Vec::new();
    verify_data.extend_from_slice(range1);
    verify_data.extend_from_slice(range2);

    log::info!("Building certificate store for PDF signature verification");
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let certs = Stack::new().unwrap();
    let flags = Pkcs7Flags::DETACHED;

    log::info!("Checking PDF content digest, CMS signature, and signer certificate chain");
    match pkcs7.verify(&certs, &store, Some(&verify_data), None, flags) {
        Ok(_) => println!("Verification successful"),
        Err(e) => eprintln!("Verification failed: {}", e),
    }
}

/// パディングされた hex 文字列から正しい DER データを抽出
fn extract_der_from_padded_hex(hex_str: &str) -> Vec<u8> {
    let bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .take(6)
        .filter_map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect();

    if bytes.len() < 2 {
        panic!("DER データが短すぎます");
    }

    let (header_len, content_len) = if bytes[1] < 0x80 {
        (2, bytes[1] as usize)
    } else {
        let num_bytes = (bytes[1] & 0x7f) as usize;
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | bytes[2 + i] as usize;
        }
        (2 + num_bytes, len)
    };

    let total = header_len + content_len;
    let hex_len = total * 2;
    hex::decode(&hex_str[..hex_len]).expect("DER hex デコードに失敗しました")
}

/// PDF 内から署名辞書を検索し、ByteRange と Contents を返す
fn find_signature_dict(data: &[u8]) -> Option<(String, String)> {
    let needle = b"/Type /Sig";
    let mut search_from = 0;
    while search_from < data.len() {
        let pos = match find_bytes(data, needle, search_from) {
            Some(p) => p,
            None => break,
        };

        let dict_start = find_bytes_rev(data, b"<<", pos)?;
        let dict_end = find_nesting_dict_end(data, dict_start)?;
        let dict_text = String::from_utf8_lossy(&data[dict_start..dict_end]);

        if let Some(byte_range) = extract_array_value(&dict_text, "/ByteRange") {
            // /Contents の hex は辞書外まで広がる可能性があるので data 全体から探す
            if let Some(contents) = extract_hex_string_from(data, dict_start) {
                return Some((byte_range, contents));
            }
        }

        search_from = pos + needle.len();
    }
    None
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

/// /Contents <hex> の hex 文字列を抽出
fn extract_hex_string_from(data: &[u8], search_from: usize) -> Option<String> {
    let needle = b"/Contents <";
    let pos = find_bytes(data, needle, search_from)?;
    let hex_start = pos + needle.len();
    let end = data[hex_start..].iter().position(|&b| b == b'>')?;
    let hex_bytes = &data[hex_start..hex_start + end];
    Some(String::from_utf8_lossy(hex_bytes).to_string())
}

/// ByteRange 配列 `[a b c d]` を解析
fn parse_byte_range(s: &str) -> Option<Vec<usize>> {
    let inner = s.trim_start_matches('[').trim_end_matches(']');
    let nums: Vec<usize> = inner
        .split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect();
    if nums.len() == 4 {
        Some(nums)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// メインディスパッチ
// ---------------------------------------------------------------------------

pub fn pdf_main(subcommand: &PdfSubcommand) {
    match subcommand {
        PdfSubcommand::Sign(args) => pdf_sign(args),
        PdfSubcommand::Verify(args) => pdf_verify(args),
    }
}
