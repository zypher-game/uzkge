use crate::{
    build_cs::{prove_matchmaking, verify_matchmaking, N},
    gen_params::{gen_prover_params, get_verifier_params},
};
use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use zplonk::anemoi::{AnemoiJive, AnemoiJive254};

#[test]
fn test_matchmaking() {
    let mut rng = ChaChaRng::from_entropy();

    let inputs = (1..=N)
        .into_iter()
        .map(|i| Fr::from(i as u64))
        .collect::<Vec<_>>();
    let committed_seed = Fr::rand(&mut rng);
    let random_number = Fr::rand(&mut rng);

    let committment = AnemoiJive254::eval_variable_length_hash(&[committed_seed]);

    let prover_params = gen_prover_params().unwrap();
    let verifier_params = get_verifier_params().unwrap();

    let (proof, outout) = prove_matchmaking(
        &mut rng,
        &inputs,
        &committed_seed,
        &random_number,
        &prover_params,
    )
    .unwrap();

    verify_matchmaking(
        &verifier_params,
        &inputs,
        &outout,
        &committment,
        &random_number,
        &proof,
    )
    .unwrap()
}
