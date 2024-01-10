use ark_bn254::{Fq as Fq_254, G1Affine};
use ark_ec::{AdditiveGroup, AffineRepr};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand_chacha::{
    rand_core::{CryptoRng, RngCore, SeedableRng},
    ChaChaRng,
};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use wasm_bindgen::prelude::*;
use zplonk::{
    poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254, turboplonk::indexer::PlonkProof,
};

#[inline(always)]
pub(crate) fn error_to_jsvalue<T: Display>(e: T) -> JsValue {
    JsValue::from_str(&e.to_string())
}

pub fn default_prng() -> impl RngCore + CryptoRng {
    ChaChaRng::from_entropy()
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct BigNumber {
    _isBigNumber: bool,
    _hex: String,
}

pub fn hex_to_scalar(hex: &str) -> Result<Fr, JsValue> {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(error_to_jsvalue)?;
    if bytes.len() != 32 {
        return Err(error_to_jsvalue("Bytes length not 32"));
    }
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

pub fn scalar_to_hex(scalar: &Fr) -> String {
    let bytes = scalar.into_bigint().to_bytes_be();
    format!("0x{}", hex::encode(&bytes))
}

pub fn hex_to_point(hex: &str) -> Result<EdwardsProjective, JsValue> {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(error_to_jsvalue)?;
    EdwardsProjective::deserialize_with_mode(bytes.as_slice(), Compress::Yes, Validate::Yes)
        .map_err(error_to_jsvalue)
}

pub fn point_to_hex(point: &EdwardsProjective) -> String {
    let mut bytes = Vec::new();
    point
        .serialize_with_mode(&mut bytes, Compress::Yes)
        .unwrap();
    format!("0x{}", hex::encode(&bytes))
}

pub fn point_to_uncompress(point: &EdwardsProjective) -> (String, String) {
    let affine = EdwardsAffine::from(*point);
    let x_bytes = affine.x.into_bigint().to_bytes_be();
    let y_bytes = affine.y.into_bigint().to_bytes_be();

    (
        format!("0x{}", hex::encode(&x_bytes)),
        format!("0x{}", hex::encode(&y_bytes)),
    )
}

pub fn uncompress_to_point(x_str: &str, y_str: &str) -> Result<EdwardsProjective, JsValue> {
    let x_hex = x_str.trim_start_matches("0x");
    let y_hex = y_str.trim_start_matches("0x");
    let x_bytes = hex::decode(x_hex).map_err(error_to_jsvalue)?;
    let y_bytes = hex::decode(y_hex).map_err(error_to_jsvalue)?;

    let x = Fq::from_be_bytes_mod_order(&x_bytes);
    let y = Fq::from_be_bytes_mod_order(&y_bytes);
    let affine = EdwardsAffine::new(x, y);

    Ok(affine.into())
}

pub fn export_proof(proof: &PlonkProof<KZGCommitmentSchemeBN254>) -> String {
    fn convert<F: PrimeField>(x: &F) -> String {
        let x = x.into_bigint().to_bytes_be();

        let mut res = String::from("");
        for i in x {
            let tmp = format!("{:02x}", i);
            res += &tmp;
        }

        res
    }

    let mut res = String::from("0x");

    for cm_q in proof.cm_w_vec.iter() {
        let tmp: G1Affine = cm_q.0.into();
        let (x, y) = tmp.xy().unwrap_or((Fq_254::ZERO, Fq_254::ZERO));
        let x = convert(&x);
        res += &x;
        let y = convert(&y);
        res += &y;
    }

    for cm_w_sel in proof.cm_w_sel_vec.iter() {
        let tmp: G1Affine = cm_w_sel.0.into();
        let (x, y) = tmp.xy().unwrap_or((Fq_254::ZERO, Fq_254::ZERO));
        let x = convert(&x);
        res += &x;
        let y = convert(&y);
        res += &y;
    }

    for cm_t in proof.cm_t_vec.iter() {
        let tmp: G1Affine = cm_t.0.into();
        let (x, y) = tmp.xy().unwrap_or((Fq_254::ZERO, Fq_254::ZERO));
        let x = convert(&x);
        res += &x;
        let y = convert(&y);
        res += &y;
    }

    {
        let tmp: G1Affine = proof.cm_z.0.into();
        let (x, y) = tmp.xy().unwrap_or((Fq_254::ZERO, Fq_254::ZERO));
        let x = convert(&x);
        res += &x;
        let y = convert(&y);
        res += &y;
    }

    {
        let x = convert(&proof.prk_3_poly_eval_zeta);
        res += &x;
    }

    {
        let x = convert(&proof.prk_4_poly_eval_zeta);
        res += &x;
    }

    for x in proof.w_polys_eval_zeta.iter() {
        let x = convert(x);
        res += &x;
    }

    for x in proof.w_polys_eval_zeta_omega.iter() {
        let x = convert(x);
        res += &x;
    }

    {
        let x = convert(&proof.z_eval_zeta_omega);
        res += &x;
    }

    for x in proof.s_polys_eval_zeta.iter() {
        let x = convert(x);
        res += &x;
    }

    {
        let x = convert(&proof.q_ecc_poly_eval_zeta);
        res += &x;
    }

    for x in proof.w_sel_polys_eval_zeta.iter() {
        let x = convert(x);
        res += &x;
    }

    {
        let tmp: G1Affine = proof.opening_witness_zeta.0.into();
        let (x, y) = tmp.xy().unwrap_or((Fq_254::ZERO, Fq_254::ZERO));
        let x = convert(&x);
        res += &x;
        let y = convert(&y);
        res += &y;
    }

    {
        let tmp: G1Affine = proof.opening_witness_zeta_omega.0.into();
        let (x, y) = tmp.xy().unwrap_or((Fq_254::ZERO, Fq_254::ZERO));
        let x = convert(&x);
        res += &x;
        let y = convert(&y);
        res += &y;
    }

    res
}
