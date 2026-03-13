use asn1_rs::FromBer;
use clap::{Args, Subcommand};
use myna::reader::MynaReader;
use myna::utils;

#[derive(Debug, Args)]
pub struct PinArgs {
    /// 暗証番号(4桁)
    #[arg(short, long)]
    pin: Option<String>,
}

#[derive(Subcommand)]
pub enum TextSubcommand {
    /// AP基本情報を表示
    BasicInfo,
    /// 個人番号を表示
    Mynumber(PinArgs),
    /// 4属性を表示
    Attrs(PinArgs),
}

pub fn main(_app: &crate::App, subcommand: &TextSubcommand) {
    match subcommand {
        TextSubcommand::BasicInfo => basic_info(),
        TextSubcommand::Mynumber(args) => mynumber(args),
        TextSubcommand::Attrs(args) => attrs(args),
    }
}

fn basic_info() {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_text_ap();
    reader
        .select_ef("0005")
        .expect("EF 0005の選択に失敗しました");
    let encoded = reader.read_binary_all().expect("READ BINARYに失敗しました");
    let (_rem, payload) = asn1_rs::Any::from_ber(&encoded).expect("parse failed");
    let (rem, apid) = asn1_rs::Any::from_ber(payload.data).expect("parse failed");
    println!("APID: {}", hex::encode(apid.data));
    let (_rem, pubkey_id) = asn1_rs::Any::from_ber(rem).expect("parse failed");
    println!("公開鍵ID: {}", hex::encode(pubkey_id.data));
}

fn input_pin(args: &PinArgs) -> String {
    let pin = utils::prompt_input("暗証番号(4桁): ", &args.pin);
    utils::validate_4digit_pin(&pin).expect("暗証番号が不正です");
    pin
}

fn mynumber(args: &PinArgs) {
    let pin = input_pin(args);
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_text_ap();
    reader
        .select_ef("0011")
        .expect("EF 0011の選択に失敗しました");
    reader.verify_pin(&pin).expect("verify pin failed");
    reader
        .select_ef("0001")
        .expect("EF 0001の選択に失敗しました");
    let encoded = reader.read_binary(0, 17).expect("READ BINARYに失敗しました");
    let (_rem, res) = asn1_rs::Any::from_ber(&encoded).expect("parse failed");
    let mynumber = std::str::from_utf8(res.data).expect("個人番号のUTF-8変換に失敗しました");
    println!("{}", mynumber);
}

fn attrs(args: &PinArgs) {
    let pin = input_pin(args);
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_text_ap();
    reader
        .select_ef("0011")
        .expect("EF 0011の選択に失敗しました");
    reader.verify_pin(&pin).expect("verify pin failed");
    reader
        .select_ef("0002")
        .expect("EF 0002の選択に失敗しました");
    let encoded = reader.read_binary_all().expect("READ BINARYに失敗しました");
    let (_rem, res) = asn1_rs::Any::from_ber(&encoded).expect("parse failed");
    let (rem, _res) = asn1_rs::Any::from_ber(res.data).expect("parse failed");
    let (rem, res) = asn1_rs::Any::from_ber(rem).expect("parse failed");
    let name = std::str::from_utf8(res.data).expect("氏名のUTF-8変換に失敗しました");
    println!("氏名    : {}", name);
    let (rem, res) = asn1_rs::Any::from_ber(rem).expect("parse failed");
    let addr = std::str::from_utf8(res.data).expect("住所のUTF-8変換に失敗しました");
    println!("住所    : {}", addr);
    let (rem, res) = asn1_rs::Any::from_ber(rem).expect("parse failed");
    let birth = std::str::from_utf8(res.data).expect("生年月日のUTF-8変換に失敗しました");
    println!("生年月日: {}", birth);
    let (_rem, res) = asn1_rs::Any::from_ber(rem).expect("parse failed");
    let sex = std::str::from_utf8(res.data).expect("性別のUTF-8変換に失敗しました");
    println!("性別    : {}", sex);
}
