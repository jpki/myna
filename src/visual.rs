use crate::ber;
use crate::error::Error;
use crate::reader::MynaReader;
use crate::utils;

const VISUAL_AID: &str = "D3921000310001010402";

pub struct VisualAP<'a> {
    pub reader: &'a mut MynaReader,
}

impl MynaReader {
    pub fn visual_ap(&mut self) -> Result<VisualAP<'_>, Error> {
        let aid = utils::hex_decode(VISUAL_AID)?;
        self.select_df(&aid)?;
        Ok(VisualAP { reader: self })
    }
}

fn ber_err(e: impl std::fmt::Display) -> Error {
    Error::new(format!("BERデコードに失敗しました: {}", e))
}

impl<'a> VisualAP<'a> {
    pub fn close(self) {}

    /// 券面確認APから顔写真を取得する
    pub fn photo(&mut self, mynumber: &str) -> Result<Vec<u8>, Error> {
        self.reader.select_ef("0013")?;
        self.reader.verify_pin(mynumber)?;
        self.reader.select_ef("0002")?;
        let encoded = self.reader.read_binary_all()?;

        let (_rem, payload) = ber::parse_tlv(&encoded).map_err(ber_err)?;
        let mut rem = payload.data;
        // 構造: Header(33), Birth(34), Sex(35), PublicKey(36), Name(37), Addr(38), Photo(39), ...
        for _ in 0..6 {
            let (next, _) = ber::parse_tlv(rem).map_err(ber_err)?;
            rem = next;
        }
        let (_rem, photo_data) = ber::parse_tlv(rem).map_err(ber_err)?;
        Ok(photo_data.data.to_vec())
    }
}
