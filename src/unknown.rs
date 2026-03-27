use crate::error::Error;
use crate::reader::MynaReader;
use crate::utils;

const UNKNOWN_AID: &str = "D3921000310001010100";

pub struct UnknownAP<'a> {
    pub reader: &'a mut MynaReader,
}

impl MynaReader {
    pub fn unknown_ap(&mut self) -> Result<UnknownAP<'_>, Error> {
        let aid = utils::hex_decode(UNKNOWN_AID)?;
        self.select_df(&aid)?;
        Ok(UnknownAP { reader: self })
    }
}

impl<'a> UnknownAP<'a> {
    pub fn close(self) {}

    pub fn read_number(&mut self) -> Result<Vec<u8>, Error> {
        let data = self.reader.read_record(1, 1)?;
        let (_, tlv) = crate::ber::parse_tlv(&data)
            .map_err(|e| Error::new(format!("BERデコードに失敗しました: {}", e)))?;
        Ok(tlv.data.to_vec())
    }
}
