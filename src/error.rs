use std::{
    error::Error,
    fmt::{self, Display},
    io,
};

#[derive(Debug)]
pub enum SdkError {
    Io(io::Error),
    InvalidInput(String),
    Connection(String),
    Server(String),
    Serialization(String),
}

impl Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "IO error: {error}"),
            Self::InvalidInput(message) => write!(f, "Invalid input: {message}"),
            Self::Connection(message) => write!(f, "Connection error: {message}"),
            Self::Server(message) => write!(f, "Server error: {message}"),
            Self::Serialization(message) => write!(f, "Serialization error: {message}"),
        }
    }
}

impl Error for SdkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidInput(_)
            | Self::Connection(_)
            | Self::Server(_)
            | Self::Serialization(_) => None,
        }
    }
}

impl From<io::Error> for SdkError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
