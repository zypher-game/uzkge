#[macro_use]
extern crate lazy_static;

pub mod keygen;

pub mod mask;

pub mod reveal;

pub mod build_cs;

pub mod parameters;

#[cfg(test)]
mod tests;

use ark_ed_on_bn254::EdwardsProjective;
use zplonk::chaum_pedersen::dl::ChaumPedersenDLProof;

pub use zplonk::shuffle::Ciphertext;

// TODO Fixme or multiple
pub const N_CARDS: usize = 52;

/// An Card with value
pub type Card = EdwardsProjective;

/// An reveal part card
pub type RevealCard = EdwardsProjective;

/// MaskedProof
pub type MaskedProof = ChaumPedersenDLProof;

/// RevealProof
pub type RevealProof = ChaumPedersenDLProof;

/// MaskedCard
pub type MaskedCard = Ciphertext<EdwardsProjective>;
