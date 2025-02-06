use alloc::{string::String, vec::Vec};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use uzkge::anemoi::{AnemoiJive, AnemoiJive254};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn anemoi_hash(datas: Vec<String>) -> String {
    let mut inputs: Vec<Fr> = Vec::new();
    for data in datas {
        let input =
            hex::decode(data.strip_prefix("0x").unwrap_or(&data)).expect("hex decode data error");
        let input = Fr::from_be_bytes_mod_order(&input);
        inputs.push(input);
    }

    let res = AnemoiJive254::eval_variable_length_hash(&inputs);

    format!("0x{}", hex::encode(res.into_bigint().to_bytes_be()))
}
