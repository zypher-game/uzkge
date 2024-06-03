use ark_ec::PrimeGroup;
use ark_ed_on_bn254::EdwardsProjective;
use ark_std::rand::{CryptoRng, RngCore};
use uzkge::{
    anemoi::AnemoiJive254,
    chaum_pedersen::dl::{
        prove, prove0, verify, verify0, ChaumPedersenDLParameters, ChaumPedersenDLProof,
    },
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

// The zk-friendly reveal algorithm.
pub fn reveal0<R: CryptoRng + RngCore>(
    prng: &mut R,
    keypair: &Keypair,
    masked_card: &MaskedCard,
) -> Result<(RevealCard, ChaumPedersenDLProof)> {
    let reveal = masked_card.e1 * keypair.secret;

    let parameters = ChaumPedersenDLParameters {
        g: masked_card.e1,
        h: EdwardsProjective::generator(),
    };

    let proof =
        prove0::<_, AnemoiJive254>(prng, &parameters, &keypair.secret, &reveal, &keypair.public)?;

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

// The zk-friendly verify reveal algorithm.
pub fn verify_reveal0(
    pk: &PublicKey,
    masked_card: &MaskedCard,
    reveal_card: &RevealCard,
    proof: &ChaumPedersenDLProof,
) -> Result<()> {
    let parameters = ChaumPedersenDLParameters {
        g: masked_card.e1,
        h: EdwardsProjective::generator(),
    };

    verify0::<AnemoiJive254>(&parameters, &reveal_card, pk, proof)
}

#[inline]
pub fn unmask(masked_card: &MaskedCard, reveal_cards: &[RevealCard]) -> Result<Card> {
    let aggregate: EdwardsProjective = reveal_cards.iter().sum();

    Ok(masked_card.e2 - aggregate)
}
