/// Module for keygen & Keypair.
pub mod keygen;

/// Module for mask card.
pub mod mask;

/// Module for reveal card.
pub mod reveal;

/// Module for build shuffle cs.
pub mod build_cs;

/// Module for generate prover & verifier params.
pub mod gen_params;

#[cfg(test)]
mod tests;

use ark_ed_on_bn254::EdwardsProjective;
use zplonk::chaum_pedersen::dl::ChaumPedersenDLProof;

/// re-export Ciphertext (a.k.a MaskedCard)
pub use zplonk::shuffle::Ciphertext;

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
