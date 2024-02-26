pub type Result<T> = core::result::Result<T, ZplonkError>;

/// zplonk errors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ZplonkError {
    /// Common: Could not serialize object.
    SerializationError,
    /// Common: Could not deserialize object.
    DeserializationError,
    /// Common: Unexpected parameter for method or function.
    ParameterError,
    /// Params: The program is loading verifier parameters that are not hardcoded.
    MissingVerifierParamsError,
    /// Params: The Noah library is compiled without SRS, which prevents proof generation.
    MissingSRSError,
    /// Params: Could not preprocess verifier.
    VerifierParamsError,
    /// PolyComScheme: Cannot compute the proof as sumcheck fails.
    PCSProveEvalError,
    /// PolyComScheme: The degree of the polynomial is higher than the maximum supported.
    DegreeError,
    /// Plonk: Querying a selector that does not exist.
    SelectorIndexOutOfBound,
    /// Plonk: challenge is invalid.
    ChallengeError,
    /// Plonk: Setup error.
    SetupError,
    /// Plonk: Group not found of size {0}.
    GroupNotFound(usize),
    /// Plonk: Division by zero.
    DivisionByZero,
    /// Plonk: Commitment error.
    CommitmentError,
    /// Plonk: FFT error.
    FFTError,
    /// Plonk: Function params error.
    FuncParamsError,
    /// Plonk: Proof error.
    ProofError,
    /// Plonk: Verification error.
    VerificationError,
    /// Plonk: {0}
    Message(String),
}

impl core::fmt::Display for ZplonkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ark_std::error::Error for ZplonkError {
    #[cfg(feature = "std")]
    fn description(&self) -> &str {
        Box::leak(format!("{}", self).into_boxed_str())
    }
}
