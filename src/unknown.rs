use crate::reader::MynaReader;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum UnknownSubcommand {
    /// 謎の番号
    Number,
    /// 謎の製造番号
    Manufacture,
}

pub fn main(command: &UnknownSubcommand) {
    match command {
        UnknownSubcommand::Number => run_number(),
        UnknownSubcommand::Manufacture => run_manufacture(),
    }
}

fn run_number() {
    let data = read_number();
    let s = String::from_utf8_lossy(&data);
    println!("{}", s);
}

fn run_manufacture() {
    let data = read_number();
    let s = String::from_utf8_lossy(&data);
    print!("{}", &s[2..15]);
}

pub fn read_number() -> Vec<u8> {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");

    reader.select_unknown_ap();

    // READ RECORD (SFI=1, Record=1)
    let data = reader.read_record(1, 1).expect("READ RECORDに失敗しました");

    // BER decode して value を返却
    use asn1_rs::{Any, FromBer};
    let (_, any) = Any::from_ber(&data).expect("BERデコードに失敗しました");
    any.data.to_vec()
}
