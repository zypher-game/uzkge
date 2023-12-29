use ark_std::error;
use displaydoc::Display;

/// Polynomial commitment scheme errors.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
pub enum PolyComSchemeError {
    /// Cannot compute the proof as sumcheck fails.
    PCSProveEvalError,
    /// The degree of the polynomial is higher than the maximum degree supported.
    DegreeError,
    /// Deserialize error.
    DeserializationError,
}

impl error::Error for PolyComSchemeError {
    #[cfg(feature = "std")]
    fn description(&self) -> &str {
        Box::leak(format!("{}", self).into_boxed_str())
    }
}
