use alloc::string::String;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn point_add(x1: String, y1: String, x2: String, y2: String) -> String {
    let x1 = hex::decode(x1.strip_prefix("0x").unwrap_or(&x1)).expect("hex decode x1 error");
    let x_1 = Fq::from_be_bytes_mod_order(&x1);

    let y1 = hex::decode(y1.strip_prefix("0x").unwrap_or(&y1)).expect("hex decode y1 error");
    let y_1 = Fq::from_be_bytes_mod_order(&y1);

    let x2 = hex::decode(x2.strip_prefix("0x").unwrap_or(&x2)).expect("hex decode x2 error");
    let x_2 = Fq::from_be_bytes_mod_order(&x2);

    let y2 = hex::decode(y2.strip_prefix("0x").unwrap_or(&y2)).expect("hex decode y2 error");
    let y_2 = Fq::from_be_bytes_mod_order(&y2);

    let mut ret = [0u8; 64];
    let p1 = EdwardsAffine::new(x_1, y_1);
    let p2 = EdwardsAffine::new(x_2, y_2);
    let p3 = p1 + p2;

    if let Some((r_x, r_y)) = p3.into_affine().xy() {
        ret[0..32].copy_from_slice(&r_x.into_bigint().to_bytes_be());
        ret[32..64].copy_from_slice(&r_y.into_bigint().to_bytes_be());
    }
    format!("0x{}", hex::encode(ret.to_vec()))
}

#[wasm_bindgen]
pub fn scalar_mul(s: String, x: String, y: String) -> String {
    let s = hex::decode(s.strip_prefix("0x").unwrap_or(&s)).expect("hex decode s error");
    let s = Fr::from_be_bytes_mod_order(&s);

    let x = hex::decode(x.strip_prefix("0x").unwrap_or(&x)).expect("hex decode s error");
    let x = Fq::from_be_bytes_mod_order(&x);

    let y = hex::decode(y.strip_prefix("0x").unwrap_or(&y)).expect("hex decode s error");
    let y = Fq::from_be_bytes_mod_order(&y);

    let mut ret = [0u8; 64];
    let p = EdwardsAffine::new(x, y);
    let p2 = p * s;

    if let Some((r_x, r_y)) = p2.into_affine().xy() {
        ret[0..32].copy_from_slice(&r_x.into_bigint().to_bytes_be());
        ret[32..64].copy_from_slice(&r_y.into_bigint().to_bytes_be());
    }
    format!("0x{}", hex::encode(ret.to_vec()))
}
