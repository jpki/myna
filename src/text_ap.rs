use crate::error::Error;
use crate::reader::MynaReader;
use crate::utils;

const TEXT_AID: &str = "D3921000310001010408";

pub struct TextAP<'a> {
    pub reader: &'a mut MynaReader,
}

impl MynaReader {
    pub fn text_ap(&mut self) -> Result<TextAP<'_>, Error> {
        let aid = utils::hex_decode(TEXT_AID)?;
        self.select_df(&aid)?;
        Ok(TextAP { reader: self })
    }
}

impl<'a> TextAP<'a> {
    pub fn close(self) {}
}
