use std::fmt;

#[derive(Clone, Eq, PartialEq)]
pub struct Error {
    message: String,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn with_source(message: impl Into<String>, source: impl fmt::Display) -> Self {
        Self::new(format!("{}: {}", message.into(), source))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

impl From<crate::apdu::APDUError> for Error {
    fn from(e: crate::apdu::APDUError) -> Self {
        Self::new(format!("{}", e))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(format!("{}", e))
    }
}

impl From<base16ct::Error> for Error {
    fn from(e: base16ct::Error) -> Self {
        Self::new(format!("{}", e))
    }
}

impl From<base64ct::Error> for Error {
    fn from(e: base64ct::Error) -> Self {
        Self::new(format!("{}", e))
    }
}
