use ark_std::error;
use displaydoc::Display;

pub type Result<T> = core::result::Result<T, SetUpError>;

#[derive(Debug, Clone, Eq, PartialEq, Display)]
#[allow(missing_docs)]
pub enum SetUpError {
    /// The program is loading verifier parameters that are not hardcoded. Such parameters must be created first.
    MissingVerifierParamsError,
    /// Could not deserialize object.
    DeserializationError,
    /// Could not serialize object.
    SerializationError,
    /// The Noah library is compiled without SRS, which prevents proof generation.
    MissingSRSError,
    /// Could not preprocess verifier.
    VerifierParamsError,
    /// Unexpected parameter for method or function.
    ParameterError,
}

impl error::Error for SetUpError {
    #[cfg(feature = "std")]
    fn description(&self) -> &str {
        Box::leak(format!("{}", self).into_boxed_str())
    }
}
