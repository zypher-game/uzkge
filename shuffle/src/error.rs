use thiserror::Error;

#[derive(Error,Debug)]
pub enum ShuffleError {
    /// Decode error 
    #[error("Error in decoding value : {0}")]
    DecodeError(String),
    #[error("Hex error:{0}")]
    HexError(#[from] hex::FromHexError),
    #[error("{0}")]
    UzkgeError(uzkge::errors::UzkgeError),
    #[error("Range Error : {0}")]
    RangeError(String),
    #[error("Bincode Error : {0}")]
    BincodeError(#[from] bincode::Error)
}
 
pub type ShuffleResult<T> = Result<T, ShuffleError>;