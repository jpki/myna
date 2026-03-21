use std::collections::HashMap;
use crate::apdu::{CommandAPDU, ResponseAPDU};
use crate::utils;

pub const JPKI_AID: &str = "D392f000260100000001";
pub const TEXT_AID: &str = "D3921000310001010408";
pub const VISUAL_AID: &str = "D3921000310001010402";
pub const UNKNOWN_AID: &str = "D3921000310001010100";

type SignFn = Box<dyn FnMut(&[u8]) -> Vec<u8>>;

pub struct DummyCardState {
    current_df: Option<String>,
    current_ef: Option<String>,
    files: HashMap<(String, String), Vec<u8>>,
    pins: HashMap<(String, String), (String, u8)>,
    sign_fn: Option<SignFn>,
}

impl Default for DummyCardState {
    fn default() -> Self {
        Self::new()
    }
}

impl DummyCardState {
    pub fn new() -> Self {
        Self {
            current_df: None,
            current_ef: None,
            files: HashMap::new(),
            pins: HashMap::new(),
            sign_fn: None,
        }
    }

    pub fn add_file(&mut self, df: &str, ef: &str, data: Vec<u8>) {
        self.files.insert((df.to_lowercase(), ef.to_lowercase()), data);
    }

    pub fn add_pin(&mut self, df: &str, ef: &str, pin: &str, attempts: u8) {
        self.pins.insert(
            (df.to_lowercase(), ef.to_lowercase()),
            (pin.to_string(), attempts),
        );
    }

    pub fn set_sign_fn(&mut self, f: impl FnMut(&[u8]) -> Vec<u8> + 'static) {
        self.sign_fn = Some(Box::new(f));
    }

    fn current_key(&self) -> (String, String) {
        let df = self.current_df.as_ref().expect("No DF selected");
        let ef = self.current_ef.as_ref().expect("No EF selected");
        (df.clone(), ef.clone())
    }

    pub fn process(&mut self, cmd: CommandAPDU) -> ResponseAPDU {
        match cmd.ins() {
            0xA4 => self.handle_select(&cmd),
            0xB0 => self.handle_read_binary(&cmd),
            0xB2 => self.handle_read_record(&cmd),
            0x20 if cmd.data().is_empty() => self.handle_read_pin(),
            0x20 => self.handle_verify(&cmd),
            0x24 => self.handle_change_pin(&cmd),
            0x2A => self.handle_signature(&cmd),
            _ => ResponseAPDU::new(&[0x6D, 0x00]),
        }
    }

    fn handle_select(&mut self, cmd: &CommandAPDU) -> ResponseAPDU {
        match cmd.p1() {
            0x04 => {
                // SELECT DF
                let aid = utils::hex_encode(cmd.data());
                self.current_df = Some(aid);
                self.current_ef = None;
                ResponseAPDU::new(&[0x90, 0x00])
            }
            0x02 => {
                // SELECT EF
                let fid = utils::hex_encode(cmd.data());
                let df = match &self.current_df {
                    Some(df) => df.clone(),
                    None => return ResponseAPDU::new(&[0x69, 0x86]),
                };
                let key = (df, fid.clone());
                if self.files.contains_key(&key) || self.pins.contains_key(&key) {
                    self.current_ef = Some(fid);
                    ResponseAPDU::new(&[0x90, 0x00])
                } else {
                    ResponseAPDU::new(&[0x6A, 0x82])
                }
            }
            _ => ResponseAPDU::new(&[0x6A, 0x86]),
        }
    }

    fn handle_read_binary(&self, cmd: &CommandAPDU) -> ResponseAPDU {
        let key = self.current_key();
        let data = match self.files.get(&key) {
            Some(d) => d,
            None => return ResponseAPDU::new(&[0x6A, 0x82]),
        };
        let offset = ((cmd.p1() as usize) << 8) | cmd.p2() as usize;
        if offset >= data.len() {
            return ResponseAPDU::new(&[0x90, 0x00]);
        }
        let remaining = data.len() - offset;
        let le = match cmd.le() {
            Some(0) | None => remaining, // Le=0 means max
            Some(n) => (n as usize).min(remaining),
        };
        let end = offset + le;
        let mut resp = data[offset..end].to_vec();
        resp.push(0x90);
        resp.push(0x00);
        ResponseAPDU::new(&resp)
    }

    fn handle_read_record(&self, cmd: &CommandAPDU) -> ResponseAPDU {
        let df = match &self.current_df {
            Some(df) => df.clone(),
            None => return ResponseAPDU::new(&[0x69, 0x86]),
        };
        let record = cmd.p1();
        let sfi = cmd.p2() >> 3;
        let key = (df, format!("record_{sfi}_{record}"));
        match self.files.get(&key) {
            Some(data) => {
                let mut resp = data.clone();
                resp.push(0x90);
                resp.push(0x00);
                ResponseAPDU::new(&resp)
            }
            None => ResponseAPDU::new(&[0x6A, 0x83]),
        }
    }

    fn handle_read_pin(&self) -> ResponseAPDU {
        let key = self.current_key();
        match self.pins.get(&key) {
            Some((_, attempts)) => ResponseAPDU::new(&[0x63, 0xC0 | attempts]),
            None => ResponseAPDU::new(&[0x69, 0x86]),
        }
    }

    fn handle_verify(&mut self, cmd: &CommandAPDU) -> ResponseAPDU {
        let key = self.current_key();
        let pin_input = std::str::from_utf8(cmd.data()).unwrap_or("");
        match self.pins.get_mut(&key) {
            Some((expected, attempts)) => {
                if pin_input == expected.as_str() {
                    ResponseAPDU::new(&[0x90, 0x00])
                } else {
                    *attempts = attempts.saturating_sub(1);
                    ResponseAPDU::new(&[0x63, 0xC0 | *attempts])
                }
            }
            None => ResponseAPDU::new(&[0x69, 0x86]),
        }
    }

    fn handle_change_pin(&mut self, cmd: &CommandAPDU) -> ResponseAPDU {
        let key = self.current_key();
        let new_pin = std::str::from_utf8(cmd.data()).unwrap_or("");
        match self.pins.get_mut(&key) {
            Some((pin, _)) => {
                *pin = new_pin.to_string();
                ResponseAPDU::new(&[0x90, 0x00])
            }
            None => ResponseAPDU::new(&[0x69, 0x86]),
        }
    }

    fn handle_signature(&mut self, cmd: &CommandAPDU) -> ResponseAPDU {
        match &mut self.sign_fn {
            Some(f) => {
                let sig = f(cmd.data());
                let mut resp = sig;
                resp.push(0x90);
                resp.push(0x00);
                ResponseAPDU::new(&resp)
            }
            None => ResponseAPDU::new(&[0x6D, 0x00]),
        }
    }
}
