use crate::reader::MynaReader;
use asn1_rs::{Any, FromBer};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum UnknownCommand {
    /// 謎の番号
    Number,
    //// 謎の製造番号
    Manufacture,
}

pub fn main(_app: &crate::App, command: &UnknownCommand) {
    match command {
        UnknownCommand::Number => number(),
        UnknownCommand::Manufacture => manufacture(),
    }
}

fn read_number() -> String {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");

    // AID: D3921000310001010100
    reader.select_ap("D3921000310001010100");

    // READ RECORD (SFI=1, Record=1)
    let data = reader
        .read_record(1, 1)
        .expect("READ RECORDに失敗しました");

    // BER decode して value を取得
    let (_, any) = Any::from_ber(&data).expect("BERデコードに失敗しました");
    String::from_utf8_lossy(any.data).into_owned()
}

fn number() {
    let number = read_number();
    println!("{}", number);
}

fn manufacture() {
    let number = read_number();
    print!("{}", &number[2..15]);
}
