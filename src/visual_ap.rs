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

impl<'a> VisualAP<'a> {
    pub fn close(self) {}
}
