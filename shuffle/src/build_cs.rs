use ark_bn254::Fr;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
use ark_std::rand::{CryptoRng, RngCore};
use uzkge::{
    anemoi::{AnemoiJive, AnemoiJive254},
    errors::Result,
    plonk::{
        constraint_system::shuffle::CardVar, indexer::PlonkProof, prover::prover_with_lagrange,
        verifier::verifier,
    },
    poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254,
    shuffle::{BabyJubjubShuffle, Permutation, Remark},
    utils::transcript::Transcript,
};

use crate::{
    gen_params::{ProverParams, VerifierParams},
    MaskedCard,
};

pub type ShuffleProof = PlonkProof<KZGCommitmentSchemeBN254>;
pub type TurboCS = uzkge::plonk::constraint_system::TurboCS<Fr>;

const PLONK_PROOF_TRANSCRIPT: &[u8] = b"Plonk shuffle Proof";
const N_CARDS_TRANSCRIPT: &[u8] = b"Number of cards";

pub const N_CARDS_PUBLIC: usize = 17;

pub(crate) fn build_cs<R: CryptoRng + RngCore>(
    prng: &mut R,
    aggregate_public_key: &EdwardsProjective,
    input_cards: &[MaskedCard],
) -> (TurboCS, Vec<CardVar>) {
    let n = input_cards.len();
    let mut cs = TurboCS::new();
    cs.load_anemoi_parameters::<AnemoiJive254>();
    cs.load_shuffle_remark_parameters::<_, BabyJubjubShuffle>(aggregate_public_key);

    let mut remark_card_vars = Vec::with_capacity(n);
    let mut input_card_vars = Vec::with_capacity(n);

    for input in input_cards.iter() {
        let bits = BabyJubjubShuffle::sample_random_scalar_bits(prng);
        let trace = BabyJubjubShuffle::eval_remark_with_trace(input, &bits, &aggregate_public_key);
        let input_var = cs.new_card_variable(input);
        let output_var = cs.eval_card_remark(&trace, &input_var);
        input_card_vars.push(input_var);
        remark_card_vars.push(output_var);
    }

    // only public the first 17 input cards.
    input_card_vars
        .iter()
        .take(N_CARDS_PUBLIC)
        .for_each(|c| cs.prepare_pi_card_variable(c));

    // only hash the last 35 input cards.
    let last_input_cards = input_cards
        .iter()
        .skip(N_CARDS_PUBLIC)
        .flat_map(|x| x.flatten())
        .collect::<Vec<_>>();
    let last_input_card_vars = input_card_vars
        .iter()
        .skip(N_CARDS_PUBLIC)
        .flat_map(|x| x.get_raw())
        .collect::<Vec<_>>();

    let trace = AnemoiJive254::eval_variable_length_hash_with_trace(&last_input_cards);
    let anemoi_out_var = cs.new_variable(trace.output);
    cs.anemoi_variable_length_hash::<AnemoiJive254>(&trace, &last_input_card_vars, anemoi_out_var);
    cs.prepare_pi_variable(anemoi_out_var);

    let permutation = Permutation::rand(prng, n);
    let shuffle_card_vars = cs.shuffle_card(&remark_card_vars, &permutation);
    // public all output cards.
    for card_var in shuffle_card_vars.iter() {
        cs.prepare_pi_card_variable(card_var);
    }

    // only hash the last 35 output cards.
    let last_output_card_vars = shuffle_card_vars
        .iter()
        .skip(N_CARDS_PUBLIC)
        .flat_map(|x| x.get_raw())
        .collect::<Vec<_>>();
    let last_output_cards = last_output_card_vars
        .iter()
        .map(|x| cs.witness[*x])
        .collect::<Vec<_>>();

    let trace = AnemoiJive254::eval_variable_length_hash_with_trace(&last_output_cards);
    let anemoi_out_var = cs.new_variable(trace.output);
    cs.anemoi_variable_length_hash::<AnemoiJive254>(&trace, &last_output_card_vars, anemoi_out_var);
    cs.prepare_pi_variable(anemoi_out_var);

    cs.pad();

    (cs, shuffle_card_vars)
}

pub fn prove_shuffle<R: CryptoRng + RngCore>(
    prng: &mut R,
    aggregate_public_key: &EdwardsProjective,
    input_cards: &[MaskedCard],
    prover_params: &ProverParams,
) -> Result<(ShuffleProof, Vec<MaskedCard>)> {
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
    proof: &ShuffleProof,
) -> Result<()> {
    let n = input_cards.len();
    // FIXME check n eq verifier_params

    let mut transcript = Transcript::new(PLONK_PROOF_TRANSCRIPT);
    transcript.append_u64(N_CARDS_TRANSCRIPT, n as u64);

    let mut online_inputs = vec![];

    for card in input_cards.iter().take(N_CARDS_PUBLIC) {
        online_inputs.extend_from_slice(&card.flatten());
    }

    let hash = AnemoiJive254::eval_variable_length_hash(
        &input_cards
            .iter()
            .skip(N_CARDS_PUBLIC)
            .flat_map(|x| x.flatten())
            .collect::<Vec<_>>(),
    );
    online_inputs.push(hash);

    for card in output_cards.iter() {
        online_inputs.extend_from_slice(&card.flatten());
    }

    let hash = AnemoiJive254::eval_variable_length_hash(
        &output_cards
            .iter()
            .skip(N_CARDS_PUBLIC)
            .flat_map(|x| x.flatten())
            .collect::<Vec<_>>(),
    );
    online_inputs.push(hash);

    Ok(verifier(
        &mut transcript,
        &verifier_params.shrunk_vk,
        &verifier_params.shrunk_cs,
        &verifier_params.verifier_params,
        &online_inputs,
        proof,
    )?)
}
