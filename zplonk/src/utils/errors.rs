use ark_std::error;
use displaydoc::Display;

#[derive(Debug, Clone, Eq, PartialEq, Display)]
pub enum UtilsError {
    /// Could not deserialize object.
    DeserializationError,
    /// Could not serialize object.
    SerializationError,
}

impl error::Error for UtilsError {
    #[cfg(feature = "std")]
    fn description(&self) -> &str {
        Box::leak(format!("{}", self).into_boxed_str())
    }
}
