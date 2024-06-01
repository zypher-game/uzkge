use alloc::{format, string::String, vec::Vec};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ethabi::Token;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use uzkge::{
    anemoi::{AnemoiJive, AnemoiJive254},
    gen_params::VerifierParams,
};
use wasm_bindgen::prelude::wasm_bindgen;
use zmatchmaking::{
    build_cs::{prove_matchmaking, verify_matchmaking, Proof},
    gen_params::{gen_prover_params, get_verifier_params},
};

#[wasm_bindgen]
pub fn verifier_matchmaking_params() -> String {
    let param = get_verifier_params().unwrap();

    format!("0x{}", hex::encode(bincode::serialize(&param).unwrap()))
}

#[wasm_bindgen]
pub fn generate_matchmaking_proof(
    verifier_params: String,
    rng_seed: String,
    inputs: Vec<String>,
    committed_seed: String,
    random_number: String,
) -> String {
    let verifier_params = {
        hex::decode(
            verifier_params
                .strip_prefix("0x")
                .unwrap_or(&verifier_params),
        )
        .expect("hex decode verifier_params error")
    };

    let rng_seed = {
        hex::decode(rng_seed.strip_prefix("0x").unwrap_or(&rng_seed))
            .expect("hex decode rng_seed error")
            .try_into()
            .unwrap()
    };
    let mut rng = ChaChaRng::from_seed(rng_seed);

    let mut input_param = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        let data = hex::decode(input.strip_prefix("0x").unwrap_or(&input))
            .expect(&format!("hex decode {} input error", index));
        let input = Fr::from_be_bytes_mod_order(&data);
        input_param.push(input)
    }

    let committed_seed = {
        let data = hex::decode(committed_seed.strip_prefix("0x").unwrap_or(&committed_seed))
            .expect("hex decode committed_seed error");
        Fr::from_be_bytes_mod_order(&data)
    };

    let committment = AnemoiJive254::eval_variable_length_hash(&[committed_seed]);

    let random_number = {
        let data = hex::decode(random_number.strip_prefix("0x").unwrap_or(&random_number))
            .expect("hex decode random_number error");
        Fr::from_be_bytes_mod_order(&data)
    };

    let (proof, outputs) = prove_matchmaking(
        &mut rng,
        &input_param,
        &committed_seed,
        &random_number,
        &gen_prover_params().unwrap(),
    )
    .unwrap();

    let proof = bincode::serialize(&proof).unwrap();

    let data = ethabi::encode(&[
        Token::Bytes(verifier_params),
        Token::Array(
            input_param
                .iter()
                .map(|v| Token::Bytes(v.into_bigint().to_bytes_be()))
                .collect::<Vec<_>>(),
        ),
        Token::Array(
            outputs
                .iter()
                .map(|v| Token::Bytes(v.into_bigint().to_bytes_be()))
                .collect::<Vec<_>>(),
        ),
        Token::Bytes(committment.into_bigint().to_bytes_be()),
        Token::Bytes(random_number.into_bigint().to_bytes_be()),
        Token::Bytes(proof),
    ]);
    format!("0x{}", hex::encode(data))
}

#[wasm_bindgen]
pub fn plonk_verify_matchmaking(
    verifier_params: String,
    inputs: Vec<String>,
    outputs: Vec<String>,
    commitment: String,
    random_number: String,
    proof: String,
) -> bool {
    let verifier_params: VerifierParams = {
        let data = hex::decode(
            verifier_params
                .strip_prefix("0x")
                .unwrap_or(&verifier_params),
        )
        .expect("hex decode verifier_params error");
        bincode::deserialize(&data).expect("bincode deserialize verifier_params error")
    };

    let mut input_param = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        let data = hex::decode(input.strip_prefix("0x").unwrap_or(&input))
            .expect(&format!("hex decode {} input error", index));
        let input = Fr::from_be_bytes_mod_order(&data);
        input_param.push(input)
    }

    let mut output_param = Vec::new();
    for (index, output) in outputs.iter().enumerate() {
        let data = hex::decode(output.strip_prefix("0x").unwrap_or(&output))
            .expect(&format!("hex decode {} output error", index));
        let output = Fr::from_be_bytes_mod_order(&data);
        output_param.push(output)
    }

    let commitment = {
        let data = hex::decode(commitment.strip_prefix("0x").unwrap_or(&commitment))
            .expect("hex decode commitment error");
        Fr::from_be_bytes_mod_order(&data)
    };

    let random_number = {
        let data = hex::decode(random_number.strip_prefix("0x").unwrap_or(&random_number))
            .expect("hex decode random_number error");
        Fr::from_be_bytes_mod_order(&data)
    };

    let proof: Proof = {
        let data = hex::decode(proof.strip_prefix("0x").unwrap_or(&proof))
            .expect("hex decode proof error");
        bincode::deserialize(&data).expect("bincode deserialize proof error")
    };

    verify_matchmaking(
        &verifier_params,
        &input_param,
        &output_param,
        &commitment,
        &random_number,
        &proof,
    )
    .is_ok()
}
