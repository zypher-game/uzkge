use ark_ec::PrimeGroup;
use ark_ed_on_bn254::EdwardsProjective;
use ark_std::rand::{CryptoRng, RngCore};
use uzkge::{
    chaum_pedersen::dl::{prove, verify, ChaumPedersenDLParameters, ChaumPedersenDLProof},
    errors::Result,
    utils::transcript::Transcript,
};

use crate::{
    keygen::{Keypair, PublicKey},
    Card, MaskedCard, RevealCard,
};

pub fn reveal<R: CryptoRng + RngCore>(
    prng: &mut R,
    keypair: &Keypair,
    masked_card: &MaskedCard,
) -> Result<(RevealCard, ChaumPedersenDLProof)> {
    let reveal = masked_card.e1 * keypair.secret;

    let parameters = ChaumPedersenDLParameters {
        g: masked_card.e1,
        h: EdwardsProjective::generator(),
    };
    let mut transcript = Transcript::new(b"Revealing");

    let proof = prove(
        prng,
        &parameters,
        &mut transcript,
        &keypair.secret,
        &reveal,
        &keypair.public,
    )?;

    Ok((reveal, proof))
}

pub fn verify_reveal(
    pk: &PublicKey,
    masked_card: &MaskedCard,
    reveal_card: &RevealCard,
    proof: &ChaumPedersenDLProof,
) -> Result<()> {
    let parameters = ChaumPedersenDLParameters {
        g: masked_card.e1,
        h: EdwardsProjective::generator(),
    };
    let mut transcript = Transcript::new(b"Revealing");

    verify(&parameters, &mut transcript, &reveal_card, pk, proof)
}

pub fn unmask(masked_card: &MaskedCard, reveal_cards: &[RevealCard]) -> Result<Card> {
    let aggregate: EdwardsProjective = reveal_cards.iter().sum();

    Ok(masked_card.e2 - aggregate)
}
