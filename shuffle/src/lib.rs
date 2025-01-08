/// Module for keygen & Keypair.
pub mod keygen;

/// Module for mask card.
pub mod mask;

/// Module for reveal card.
pub mod reveal;

/// Module for reveal card with a snark proof.
pub mod reveal_with_snark;

/// Module for build shuffle cs.
pub mod build_cs;

/// Module for generate prover & verifier params.
pub mod gen_params;

pub mod error;

pub mod utils;
pub mod sdk;
pub mod card_maps;

#[cfg(test)]
mod tests;

use ark_ed_on_bn254::EdwardsProjective;
use uzkge::chaum_pedersen::dl::ChaumPedersenDLProof;

pub use ark_groth16::{Groth16, ProvingKey};
pub use ark_snark::SNARK;

/// re-export Ciphertext (a.k.a MaskedCard)
pub use uzkge::shuffle::Ciphertext;

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
