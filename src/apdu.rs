use colored::Colorize;
use std::fmt;

#[derive(Debug)]
pub struct CommandAPDU {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    le: Option<u16>,
}

impl CommandAPDU {
    pub fn case1(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: vec![],
            le: None,
        }
    }
    pub fn case2(cla: u8, ins: u8, p1: u8, p2: u8, le: u16) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: vec![],
            le: Some(le),
        }
    }

    pub fn case3(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: data.to_vec(),
            le: None,
        }
    }

    #[allow(dead_code)]
    pub fn case4(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u16) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: data.to_vec(),
            le: Some(le),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4);
        bytes.push(self.cla);
        bytes.push(self.ins);
        bytes.push(self.p1);
        bytes.push(self.p2);

        let len: u16 = self.data.len() as u16;
        if len != 0 {
            if len <= 0xff {
                bytes.push(len as u8);
            } else {
                bytes.push(0);
                bytes.extend_from_slice(&len.to_be_bytes());
            }
            bytes.extend_from_slice(self.data.as_slice());
        }
        if let Some(le) = self.le {
            if le <= 0xff {
                bytes.push(le as u8);
            } else {
                // le == 0x0100 could make a more shorter command
                if self.data.is_empty() {
                    bytes.push(0);
                }
                bytes.extend_from_slice(&le.to_be_bytes());
            }
        }
        bytes
    }
}

impl fmt::LowerHex for CommandAPDU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "{}", hex::encode(bytes))
    }
}

impl fmt::Display for CommandAPDU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mask = self.cla == 0x00 && matches!(self.ins, 0x20 | 0x24);
        let cmd = format!(
            "{:02x} {:02x} {:02x} {:02x}",
            self.cla, self.ins, self.p1, self.p2
        )
        .cyan();
        write!(f, "{}", cmd).unwrap();
        let bytes = self.to_bytes();
        for b in &bytes[4..] {
            if mask {
                write!(f, " XX").unwrap();
            } else {
                write!(f, " {:02x}", b).unwrap();
            }
        }
        Ok(())
    }
}

pub struct ResponseAPDU {
    pub sw1: u8,
    pub sw2: u8,
    pub data: Vec<u8>,
}

impl ResponseAPDU {
    pub fn new(res: &[u8]) -> Self {
        if res.len() < 2 {
            Self {
                sw1: 0,
                sw2: 0,
                data: vec![],
            }
        } else if res.len() == 2 {
            Self {
                sw1: res[0],
                sw2: res[1],
                data: vec![],
            }
        } else {
            Self {
                sw1: res[res.len() - 2],
                sw2: res[res.len() - 1],
                data: res[0..res.len() - 2].to_vec(),
            }
        }
    }

    pub fn sw(&self) -> u16 {
        (self.sw1 as u16) << 8 | self.sw2 as u16
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.data.len());
        bytes.extend_from_slice(self.data.as_slice());
        bytes.push(self.sw1);
        bytes.push(self.sw2);
        bytes
    }
}

impl fmt::LowerHex for ResponseAPDU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "{}", hex::encode(bytes))
    }
}

impl fmt::Display for ResponseAPDU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut sw = format!("{:02x} {:02x}", self.sw1, self.sw2);
        if self.sw() == 0x9000 {
            sw = sw.green().to_string();
        } else {
            sw = sw.yellow().to_string();
        }
        write!(f, "{}", sw).unwrap();
        if !self.data.is_empty() {
            for b in &self.data {
                write!(f, " {:02x}", b).unwrap();
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ResponseAPDU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ResponseAPDU {{ sw: {:02x}{:02x}, data: {:?} }}",
            self.sw1, self.sw2, self.data
        )
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct APDUError {
    pub res: ResponseAPDU,
}

#[test]
fn apdu_case1() {
    let cmd = CommandAPDU::case1(1, 2, 3, 4);
    assert_eq!(format!("{cmd:x}"), "01020304");
}

#[test]
fn apdu_case2() {
    let cmd = CommandAPDU::case2(1, 2, 3, 4, 0);
    assert_eq!(format!("{cmd:x}"), "0102030400");
    let cmd = CommandAPDU::case2(1, 2, 3, 4, 1);
    assert_eq!(format!("{cmd:x}"), "0102030401");
    let cmd = CommandAPDU::case2(1, 2, 3, 4, 255);
    assert_eq!(format!("{cmd:x}"), "01020304ff");
    let cmd = CommandAPDU::case2(1, 2, 3, 4, 256);
    assert_eq!(format!("{cmd:x}"), "01020304000100");
    let cmd = CommandAPDU::case2(1, 2, 3, 4, 257);
    assert_eq!(format!("{cmd:x}"), "01020304000101");
    let cmd = CommandAPDU::case2(1, 2, 3, 4, 65535);
    assert_eq!(format!("{cmd:x}"), "0102030400ffff");

    /* 仕様上65536byte利用可能だがひとまず非対応
        let cmd = CommandAPDU::case2(1, 2, 3, 4, 65536);
        assert_eq!(format!("{}", cmd), "01020304000000");
    */
}

#[test]
fn apdu_case3() {
    let cmd = CommandAPDU::case3(1, 2, 3, 4, &[1, 2, 3]);
    assert_eq!(format!("{cmd:x}"), "0102030403010203");
    let data: [u8; 1] = [0; 1];
    let cmd = CommandAPDU::case3(1, 2, 3, 4, &data);
    assert_eq!(format!("{cmd:x}"), "010203040100");
    let data: [u8; 255] = [0; 255];
    let cmd = CommandAPDU::case3(1, 2, 3, 4, &data);
    assert_eq!(
        format!("{cmd:x}"),
        format!("01020304ff{}", hex::encode(data))
    );
    let data: [u8; 256] = [0; 256];
    let cmd = CommandAPDU::case3(1, 2, 3, 4, &data);
    assert_eq!(
        format!("{cmd:x}"),
        format!("01020304000100{}", hex::encode(data))
    );
}

#[test]
fn apdu_case4() {
    let cmd = CommandAPDU::case4(1, 2, 3, 4, &[5, 6, 7], 8);
    assert_eq!(format!("{cmd:x}"), "010203040305060708");

    let data: [u8; 255] = [0; 255];
    let cmd = CommandAPDU::case4(1, 2, 3, 4, &data, 255);
    assert_eq!(
        format!("{cmd:x}"),
        format!("01020304ff{}ff", hex::encode(data))
    );
    let data: [u8; 255] = [0; 255];
    let cmd = CommandAPDU::case4(1, 2, 3, 4, &data, 256);
    assert_eq!(
        format!("{cmd:x}"),
        format!("01020304ff{}0100", hex::encode(data))
    );
    let data: [u8; 256] = [0; 256];
    let cmd = CommandAPDU::case4(1, 2, 3, 4, &data, 256);
    assert_eq!(
        format!("{cmd:x}"),
        format!("01020304000100{}0100", hex::encode(data))
    );
}

#[test]
fn res_new() {
    let res = ResponseAPDU::new(&vec![]); // invalid
    assert_eq!(format!("{res:x}"), "0000");
    let res = ResponseAPDU::new(&vec![1]); // invalid
    assert_eq!(format!("{res:x}"), "0000");
    let res = ResponseAPDU::new(&vec![1, 2]);
    assert_eq!(format!("{res:x}"), "0102");
    let res = ResponseAPDU::new(&vec![1, 2, 3]);
    assert_eq!(format!("{res:x}"), "010203");
    let res = ResponseAPDU::new(&vec![1, 2, 3, 4]);
    assert_eq!(format!("{res:x}"), "01020304");
}
