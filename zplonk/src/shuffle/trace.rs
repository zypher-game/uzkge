use ark_ff::Field;

use super::N_SELECT_BITS;
use crate::turboplonk::constraint_system::turbo::N_WIRE_SELECTORS;

/// The structure for the trace of shuffle remark.
#[derive(Default, Clone)]
pub struct RemarkTrace<F: Field> {
    /// The bits of the random scalar.
    pub bits: Vec<[F; N_WIRE_SELECTORS]>,
    /// The intermediate values for each computation.
    pub intermediate_values: Vec<[F; N_SELECT_BITS]>,
    /// The output.
    pub output: [F; N_SELECT_BITS],
    /// The round of computation.
    pub n_round: usize,
}
