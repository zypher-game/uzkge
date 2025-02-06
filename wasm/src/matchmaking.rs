use alloc::{format, string::String, vec::Vec};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{Deserialize, Serialize};
use uzkge::gen_params::VerifierParams;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zmatchmaking::{
    build_cs::{prove_matchmaking, verify_matchmaking, Proof},
    gen_params::{gen_prover_params, get_verifier_params},
};

#[wasm_bindgen]
pub fn verifier_matchmaking_params() -> String {
    let param = get_verifier_params().unwrap();

    format!("0x{}", hex::encode(bincode::serialize(&param).unwrap()))
}

#[derive(Serialize, Deserialize)]
struct MatchmakingProofReturn {
    outputs: Vec<String>,
    proof: String,
}

#[wasm_bindgen]
pub fn generate_matchmaking_proof(
    rng_seed: String,
    inputs: Vec<String>,
    committed_seed: String,
    random_number: String,
) -> JsValue {
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

    let ret = MatchmakingProofReturn {
        outputs: outputs
            .iter()
            .map(|v| format!("0x{}", hex::encode(v.into_bigint().to_bytes_be())))
            .collect::<Vec<_>>(),
        proof: format!("0x{}", hex::encode(proof)),
    };

    serde_wasm_bindgen::to_value(&ret).unwrap()
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
