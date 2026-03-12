use asn1_rs::FromBer;
use clap::{Args, Subcommand};
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

pub fn main(_app: &crate::App, subcommand: &VisualSubcommand) {
    match subcommand {
        VisualSubcommand::Photo(args) => photo(args),
    }
}

fn photo(args: &PhotoArgs) {
    let pin = utils::prompt_input("暗証番号(4桁): ", &args.pin);
    utils::validate_4digit_pin(&pin).expect("暗証番号が不正です");

    // まずマイナンバーを取得
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_text_ap();
    reader
        .select_ef("0011")
        .expect("EF 0011の選択に失敗しました");
    reader
        .verify_pin(&pin)
        .expect("暗証番号の認証に失敗しました");
    reader
        .select_ef("0001")
        .expect("EF 0001の選択に失敗しました");
    let encoded = reader.read_binary(0, 17);
    let (_rem, res) = asn1_rs::Any::from_ber(&encoded).expect("parse failed");
    let mynumber = std::str::from_utf8(res.data).expect("マイナンバーのUTF-8変換に失敗しました");

    // 券面確認APを選択してPIN認証
    reader.select_visual_ap();
    reader
        .select_ef("0013")
        .expect("EF 0013の選択に失敗しました");
    reader
        .verify_pin(mynumber)
        .expect("マイナンバー認証に失敗しました");

    // 券面情報を読み取り
    reader
        .select_ef("0002")
        .expect("EF 0002の選択に失敗しました");
    let encoded = reader.read_binary_all();

    // ASN.1をパース
    let (_rem, payload) = asn1_rs::Any::from_ber(&encoded).expect("parse failed");
    let mut rem = payload.data;

    // 構造: Header(33), Birth(34), Sex(35), PublicKey(36), Name(37), Addr(38), Photo(39), ...
    // Private tag を6回スキップして Photo(tag 39) を取得
    for _ in 0..6 {
        let (next, _) = asn1_rs::Any::from_ber(rem).expect("parse failed");
        rem = next;
    }
    let (_rem, photo_data) = asn1_rs::Any::from_ber(rem).expect("parse failed");

    // 写真データを出力
    if args.output == "-" {
        io::stdout()
            .write_all(photo_data.data)
            .expect("標準出力への書き込みに失敗しました");
    } else {
        let mut file = File::create(&args.output).expect("ファイルを作成できませんでした");
        file.write_all(photo_data.data)
            .expect("ファイルへの書き込みに失敗しました");
        println!("写真を保存しました: {}", args.output);
    }
}
