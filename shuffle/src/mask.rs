use ark_ec::PrimeGroup;
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_std::rand::{CryptoRng, RngCore};
use zplonk::{
    chaum_pedersen::dl::{prove, verify, ChaumPedersenDLParameters, ChaumPedersenDLProof},
    errors::Result,
    utils::transcript::Transcript,
};

use crate::{keygen::PublicKey, Card, MaskedCard};

/// Return an ElGamal ciphertext pair as `(r * G, m * G + r * pk)`
pub fn mask<R: CryptoRng + RngCore>(
    prng: &mut R,
    shared_key: &PublicKey,
    card: &Card,
    r: &Fr,
) -> Result<(MaskedCard, ChaumPedersenDLProof)> {
    let base = EdwardsProjective::generator();
    let e1 = base * r;
    let e2 = card + (*shared_key * r);

    // Map to Chaum-Pedersen
    let ce2 = e2 - card;

    let parameters = ChaumPedersenDLParameters {
        g: base,
        h: *shared_key,
    };
    let mut transcript = Transcript::new(b"Masking");

    let proof = prove(prng, &parameters, &mut transcript, r, &e1, &ce2)?;

    Ok((MaskedCard { e1, e2 }, proof))
}

pub fn verify_mask(
    shared_key: &PublicKey,
    card: &Card,
    masked_card: &MaskedCard,
    proof: &ChaumPedersenDLProof,
) -> Result<()> {
    // Map to Chaum-Pedersen
    let ce2 = masked_card.e2 - card;

    let parameters = ChaumPedersenDLParameters {
        g: EdwardsProjective::generator(),
        h: *shared_key,
    };
    let mut transcript = Transcript::new(b"Masking");

    verify(&parameters, &mut transcript, &masked_card.e1, &ce2, proof)
}
