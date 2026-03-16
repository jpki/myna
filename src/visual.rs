use asn1_rs::FromBer;
use clap::{Args, Subcommand};
use myna::error::Error;
use myna::reader::MynaReader;
use myna::utils;
use std::fs::File;
use std::io::{self, Write};

#[derive(Debug, Args)]
pub struct PhotoArgs {
    /// 暗証番号(4桁)
    #[arg(short, long)]
    pin: Option<String>,
    /// 出力ファイル (JPEG2000)
    #[arg(short, long)]
    output: String,
}

#[derive(Subcommand)]
pub enum VisualSubcommand {
    /// 顔写真を取得
    Photo(PhotoArgs),
}

pub fn main(_app: &crate::App, subcommand: &VisualSubcommand) -> Result<(), Error> {
    match subcommand {
        VisualSubcommand::Photo(args) => photo(args),
    }
}

fn ber_err(e: impl std::fmt::Display) -> Error {
    Error::new(format!("BERデコードに失敗しました: {}", e))
}

fn photo(args: &PhotoArgs) -> Result<(), Error> {
    let pin = utils::prompt_input("暗証番号(4桁): ", &args.pin);
    utils::validate_4digit_pin(&pin)?;

    let mut reader = MynaReader::new()?;
    reader.connect()?;

    // まずマイナンバーを取得
    let text = reader.text_ap()?;
    text.reader.select_ef("0011")?;
    text.reader.verify_pin(&pin)?;
    text.reader.select_ef("0001")?;
    let encoded = text.reader.read_binary(0, 17)?;
    let (_rem, res) = asn1_rs::Any::from_ber(&encoded).map_err(ber_err)?;
    let mynumber = std::str::from_utf8(res.data)
        .map_err(|e| Error::new(format!("マイナンバーのUTF-8変換に失敗しました: {}", e)))?;
    let mynumber = mynumber.to_string();
    text.close();

    // 券面確認APを選択してPIN認証
    let visual = reader.visual_ap()?;
    visual.reader.select_ef("0013")?;
    visual.reader.verify_pin(&mynumber)?;

    // 券面情報を読み取り
    visual.reader.select_ef("0002")?;
    let encoded = visual.reader.read_binary_all()?;

    // ASN.1をパース
    let (_rem, payload) = asn1_rs::Any::from_ber(&encoded).map_err(ber_err)?;
    let mut rem = payload.data;

    // 構造: Header(33), Birth(34), Sex(35), PublicKey(36), Name(37), Addr(38), Photo(39), ...
    // Private tag を6回スキップして Photo(tag 39) を取得
    for _ in 0..6 {
        let (next, _) = asn1_rs::Any::from_ber(rem).map_err(ber_err)?;
        rem = next;
    }
    let (_rem, photo_data) = asn1_rs::Any::from_ber(rem).map_err(ber_err)?;

    // 写真データを出力
    if args.output == "-" {
        io::stdout()
            .write_all(photo_data.data)
            .map_err(|e| Error::new(format!("標準出力への書き込みに失敗しました: {}", e)))?;
    } else {
        let mut file = File::create(&args.output)
            .map_err(|e| Error::new(format!("ファイルを作成できませんでした: {}", e)))?;
        file.write_all(photo_data.data)
            .map_err(|e| Error::new(format!("ファイルへの書き込みに失敗しました: {}", e)))?;
        println!("写真を保存しました: {}", args.output);
    }
    Ok(())
}
