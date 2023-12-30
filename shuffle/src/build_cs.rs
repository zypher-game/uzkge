use ark_bn254::Fr;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
use ark_std::rand::{CryptoRng, RngCore};
use zplonk::{
    errors::Result,
    poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254,
    shuffle::{BabyJubjubShuffle, Permutation, Remark},
    turboplonk::{
        constraint_system::{shuffle::CardVar, TurboCS},
        indexer::PlonkProof,
        prover::prover_with_lagrange,
        verifier::verifier,
    },
    utils::transcript::Transcript,
};

use crate::{
    parameters::{ProverParams, VerifierParams},
    MaskedCard,
};

const PLONK_PROOF_TRANSCRIPT: &[u8] = b"Plonk shuffle Proof";
const N_CARDS_TRANSCRIPT: &[u8] = b"Number of cards";

pub(crate) fn build_cs<R: CryptoRng + RngCore>(
    prng: &mut R,
    aggregate_public_key: &EdwardsProjective,
    input_cards: &[MaskedCard],
) -> (TurboCS<Fr>, Vec<CardVar>) {
    let n = input_cards.len();
    let mut cs = TurboCS::new();
    cs.load_shuffle_remark_parameters::<_, BabyJubjubShuffle>(aggregate_public_key);

    let mut remark_card_vars = Vec::with_capacity(n);

    for input in input_cards.iter() {
        let bits = BabyJubjubShuffle::sample_random_scalar_bits(prng);
        let trace = BabyJubjubShuffle::eval_remark_with_trace(input, &bits, &aggregate_public_key);
        let input_var = cs.new_card_variable(input);
        cs.prepare_pi_card_variable(&input_var);
        let output_var = cs.eval_card_remark(&trace, &input_var);
        remark_card_vars.push(output_var);
    }

    let permutation = Permutation::rand(prng, n);
    let shuffle_card_vars = cs.shuffle_card(&remark_card_vars, &permutation);
    for card_var in shuffle_card_vars.iter() {
        cs.prepare_pi_card_variable(card_var);
    }

    cs.pad();

    (cs, shuffle_card_vars)
}

pub fn prove_shuffle<R: CryptoRng + RngCore>(
    prng: &mut R,
    aggregate_public_key: &EdwardsProjective,
    input_cards: &[MaskedCard],
    prover_params: &ProverParams,
) -> Result<(PlonkProof<KZGCommitmentSchemeBN254>, Vec<MaskedCard>)> {
    let n = input_cards.len();
    // FIXME check n eq prover_params

    let (mut cs, output_vars) = build_cs(prng, aggregate_public_key, input_cards);
    let witness = cs.get_and_clear_witness();

    let mut transcript = Transcript::new(PLONK_PROOF_TRANSCRIPT);
    transcript.append_u64(N_CARDS_TRANSCRIPT, n as u64);

    let proof = prover_with_lagrange(
        prng,
        &mut transcript,
        &prover_params.pcs,
        prover_params.lagrange_pcs.as_ref(),
        &cs,
        &prover_params.prover_params,
        &witness,
    )?;

    let mut outputs = vec![];

    for output in output_vars.iter() {
        let a = witness[output.get_first_x()];
        let b = witness[output.get_first_y()];
        let c = witness[output.get_second_x()];
        let d = witness[output.get_second_y()];

        let e2 = EdwardsAffine::new_unchecked(a, b).into();
        let e1 = EdwardsAffine::new_unchecked(c, d).into();

        outputs.push(MaskedCard::new(e1, e2))
    }

    Ok((proof, outputs))
}

pub fn verify_shuffle(
    verifier_params: &VerifierParams,
    input_cards: &[MaskedCard],
    output_cards: &[MaskedCard],
    proof: &PlonkProof<KZGCommitmentSchemeBN254>,
) -> Result<()> {
    let n = input_cards.len();
    // FIXME check n eq verifier_params

    let mut transcript = Transcript::new(PLONK_PROOF_TRANSCRIPT);
    transcript.append_u64(N_CARDS_TRANSCRIPT, n as u64);

    let mut online_inputs = vec![];

    for card in input_cards.iter() {
        online_inputs.extend_from_slice(&card.flatten());
    }

    for card in output_cards.iter() {
        online_inputs.extend_from_slice(&card.flatten());
    }

    Ok(verifier(
        &mut transcript,
        &verifier_params.shrunk_vk,
        &verifier_params.shrunk_cs,
        &verifier_params.verifier_params,
        &online_inputs,
        proof,
    )?)
}
