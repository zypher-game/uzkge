use crate::match_making::MatchMaking;
use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use zplonk::{
    anemoi::{AnemoiJive, AnemoiJive254},
    turboplonk::constraint_system::TurboCS,
};

#[test]
fn test_match_making_constraint_system() {
    let mut rng = test_rng();
    const N: usize = 50;
    let mut cs = TurboCS::<Fr>::new();
    cs.load_anemoi_parameters::<AnemoiJive254>();

    let input_vars = (1..=N)
        .into_iter()
        .map(|i| cs.new_variable(Fr::from(i as u64)))
        .collect::<Vec<_>>();
    let committed_input = Fr::rand(&mut rng);
    let committed_trace = AnemoiJive254::eval_variable_length_hash_with_trace(&[committed_input]);
    let committed_input_var = cs.new_variable(committed_input);
    let committed_output_var = cs.new_variable(committed_trace.output);

    let random_number = Fr::rand(&mut rng);
    let random_number_var = cs.new_variable(random_number);

    let mut mmr = MatchMaking::<N, Fr>::new(
        &input_vars,
        committed_input_var,
        committed_output_var,
        &committed_trace,
        &random_number,
        random_number_var,
    );
    mmr.generate_constraints::<AnemoiJive254>(&mut cs);
    assert_eq!(cs.size, 5059);

    let witness = cs.get_and_clear_witness();
    cs.verify_witness(&witness, &[]).unwrap();
}
