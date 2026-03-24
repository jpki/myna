use clap::{Args, Subcommand};
use myna::ber;
use myna::error::Error;
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

pub fn main(_app: &crate::App, subcommand: &TextSubcommand) -> Result<(), Error> {
    match subcommand {
        TextSubcommand::BasicInfo => basic_info(),
        TextSubcommand::Mynumber(args) => mynumber(args),
        TextSubcommand::Attrs(args) => attrs(args),
    }
}

fn ber_err(e: impl std::fmt::Display) -> Error {
    Error::new(format!("BERデコードに失敗しました: {}", e))
}

fn basic_info() -> Result<(), Error> {
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let text = reader.text_ap()?;
    text.reader.select_ef("0005")?;
    let encoded = text.reader.read_binary_all()?;
    let (_rem, payload) = ber::parse_tlv(&encoded).map_err(ber_err)?;
    let (rem, apid) = ber::parse_tlv(payload.data).map_err(ber_err)?;
    println!("APID: {}", utils::hex_encode(apid.data));
    let (_rem, pubkey_id) = ber::parse_tlv(rem).map_err(ber_err)?;
    println!("公開鍵ID: {}", utils::hex_encode(pubkey_id.data));
    Ok(())
}

fn input_pin(args: &PinArgs) -> Result<String, Error> {
    let pin = utils::prompt_input("暗証番号(4桁): ", &args.pin);
    utils::validate_4digit_pin(&pin)?;
    Ok(pin)
}

fn mynumber(args: &PinArgs) -> Result<(), Error> {
    let pin = input_pin(args)?;
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let text = reader.text_ap()?;
    text.reader.select_ef("0011")?;
    text.reader.verify_pin(&pin)?;
    text.reader.select_ef("0001")?;
    let encoded = text.reader.read_binary(0, 17)?;
    let (_rem, res) = ber::parse_tlv(&encoded).map_err(ber_err)?;
    let mynumber = std::str::from_utf8(res.data)
        .map_err(|e| Error::new(format!("個人番号のUTF-8変換に失敗しました: {}", e)))?;
    println!("{}", mynumber);
    Ok(())
}

fn attrs(args: &PinArgs) -> Result<(), Error> {
    let pin = input_pin(args)?;
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let text = reader.text_ap()?;
    text.reader.select_ef("0011")?;
    text.reader.verify_pin(&pin)?;
    text.reader.select_ef("0002")?;
    let encoded = text.reader.read_binary_all()?;
    let (_rem, res) = ber::parse_tlv(&encoded).map_err(ber_err)?;
    let (rem, _res) = ber::parse_tlv(res.data).map_err(ber_err)?;
    let (rem, res) = ber::parse_tlv(rem).map_err(ber_err)?;
    let name = std::str::from_utf8(res.data)
        .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
    println!("氏名    : {}", name);
    let (rem, res) = ber::parse_tlv(rem).map_err(ber_err)?;
    let addr = std::str::from_utf8(res.data)
        .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
    println!("住所    : {}", addr);
    let (rem, res) = ber::parse_tlv(rem).map_err(ber_err)?;
    let birth = std::str::from_utf8(res.data)
        .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
    println!("生年月日: {}", birth);
    let (_rem, res) = ber::parse_tlv(rem).map_err(ber_err)?;
    let sex = std::str::from_utf8(res.data)
        .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
    println!("性別    : {}", sex);
    Ok(())
}
