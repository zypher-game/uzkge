use ark_std::error;
use displaydoc::Display;

pub type Result<T> = core::result::Result<T, ProofSystemError>;

#[derive(Debug, Clone, Eq, PartialEq, Display)]
#[allow(missing_docs)]
pub enum ProofSystemError {
    /// Querying a selector that does not exist.
    SelectorIndexOutOfBound,
    /// challenge is invalid.
    ChallengeError,
    /// Setup error.
    SetupError,
    /// Group not found of size {0}.
    GroupNotFound(usize),
    /// Division by zero.
    DivisionByZero,
    /// Commitment error.
    CommitmentError,
    /// FFT error.
    FFTError,
    /// Function params error.
    FuncParamsError,
    /// Proof error.
    ProofError,
    /// Verification error.
    VerificationError,
    /// {0}
    Message(String),
}

impl error::Error for ProofSystemError {
    #[cfg(feature = "std")]
    fn description(&self) -> &str {
        Box::leak(format!("{}", self).into_boxed_str())
    }
}
