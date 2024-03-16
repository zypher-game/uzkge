use ark_bn254::Fr;
use ark_std::rand::{CryptoRng, RngCore};
use uzkge::{
    anemoi::{AnemoiJive, AnemoiJive254},
    errors::Result,
    poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254,
    plonk::{
        constraint_system::VarIndex, indexer::PlonkProof, prover::prover_with_lagrange,
        verifier::verifier,
    },
    utils::transcript::Transcript,
};

use crate::{
    gen_params::{ProverParams, VerifierParams},
    matchmaking::Matchmaking,
};

pub type Proof = PlonkProof<KZGCommitmentSchemeBN254>;
pub type TurboCS = uzkge::plonk::constraint_system::TurboCS<Fr>;

const PLONK_PROOF_TRANSCRIPT: &[u8] = b"Plonk Matchmaking Proof";
const N_TRANSCRIPT: &[u8] = b"Number inputs";

pub const N: usize = 50;

pub(crate) fn build_cs(
    inputs: &[Fr],
    committed_seed: &Fr,
    random_number: &Fr,
) -> (TurboCS, Vec<VarIndex>) {
    let mut cs = TurboCS::new();
    cs.load_anemoi_parameters::<AnemoiJive254>();

    let input_vars = inputs
        .iter()
        .map(|i| cs.new_variable(*i))
        .collect::<Vec<_>>();
    let random_number_var = cs.new_variable(*random_number);
    let committed_trace = AnemoiJive254::eval_variable_length_hash_with_trace(&[*committed_seed]);
    let committed_input_var = cs.new_variable(*committed_seed);
    let committed_output_var = cs.new_variable(committed_trace.output);

    let mut mm = Matchmaking::<N, Fr>::new(
        &input_vars,
        committed_input_var,
        committed_output_var,
        &committed_trace,
        random_number_var,
    );
    mm.generate_constraints::<AnemoiJive254>(&mut cs);

    // public IO value
    for x in input_vars {
        cs.prepare_pi_variable(x);
    }
    for x in mm.output_vars.iter() {
        cs.prepare_pi_variable(*x);
    }
    cs.prepare_pi_variable(random_number_var);
    cs.prepare_pi_variable(committed_output_var);

    cs.pad();

    (cs, mm.output_vars)
}

pub fn prove_matchmaking<R: CryptoRng + RngCore>(
    prng: &mut R,
    inputs: &[Fr],
    committed_seed: &Fr,
    random_number: &Fr,
    prover_params: &ProverParams,
) -> Result<(Proof, Vec<Fr>)> {
    assert_eq!(inputs.len(), N);

    let (mut cs, output_vars) = build_cs(inputs, committed_seed, random_number);
    let witness = cs.get_and_clear_witness();

    let mut transcript = Transcript::new(PLONK_PROOF_TRANSCRIPT);
    transcript.append_u64(N_TRANSCRIPT, N as u64);

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
    for i in output_vars {
        outputs.push(witness[i])
    }

    Ok((proof, outputs))
}

pub fn verify_matchmaking(
    verifier_params: &VerifierParams,
    inputs: &[Fr],
    outputs: &[Fr],
    commitment: &Fr,
    random_number: &Fr,
    proof: &Proof,
) -> Result<()> {
    assert_eq!(inputs.len(), N);
    assert_eq!(outputs.len(), N);

    let mut transcript = Transcript::new(PLONK_PROOF_TRANSCRIPT);
    transcript.append_u64(N_TRANSCRIPT, N as u64);

    let mut online_inputs = vec![];
    online_inputs.extend_from_slice(inputs);
    online_inputs.extend_from_slice(outputs);
    online_inputs.push(*random_number);
    online_inputs.push(*commitment);

    Ok(verifier(
        &mut transcript,
        &verifier_params.shrunk_vk,
        &verifier_params.shrunk_cs,
        &verifier_params.verifier_params,
        &online_inputs,
        proof,
    )?)
}
