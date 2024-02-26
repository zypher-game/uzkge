use ark_bn254::Fr;
use ark_ff::{Field, One};
use ark_serialize::CanonicalSerialize;
use std::path::PathBuf;
use tera::{Context, Tera};

use crate::{
    gen_params::VerifierParams,
    poly_commit::field_polynomial::FpPolynomial,
    utils::serialization::{point_to_uncompress_be, scalar_to_bytes_be},
};

const VKE1: &str = include_str!("../../parameters/VerifierKeyExtra1.sol");
const VKE2: &str = include_str!("../../parameters/VerifierKeyExtra2.sol");
const VK: &str = include_str!("../../parameters/VerifierKey.sol");

pub fn gen_solidity_vk(vk: VerifierParams, num: usize, directory: PathBuf, full: bool) {
    let params = vk.verifier_params;
    let n = Fr::one().uncompressed_size() * 2;
    println!("the size of the constraint system: {}", params.cs_size);

    let mut vk_i = 0;
    let mut vks = vec![];
    let mut pi_poly_indices_locs = vec![];
    let mut pi_poly_lagrange_locs = vec![];

    for c in params.cm_q_vec.iter() {
        let s = hex::encode(point_to_uncompress_be(&c.0));
        vks.push((hex_i(vk_i), fmt_s(&s[..n])));
        vk_i += 32;
        vks.push((hex_i(vk_i), fmt_s(&s[n..])));
        vk_i += 32;
    }
    for c in params.cm_s_vec.iter() {
        let s = hex::encode(point_to_uncompress_be(&c.0));
        vks.push((hex_i(vk_i), fmt_s(&s[..n])));
        vk_i += 32;
        vks.push((hex_i(vk_i), fmt_s(&s[n..])));
        vk_i += 32;
    }

    let s = hex::encode(point_to_uncompress_be(&params.cm_qb.0));
    vks.push((hex_i(vk_i), fmt_s(&s[..n])));
    vk_i += 32;
    vks.push((hex_i(vk_i), fmt_s(&s[n..])));
    vk_i += 32;

    for c in params.cm_prk_vec.iter() {
        let s = hex::encode(point_to_uncompress_be(&c.0));
        vks.push((hex_i(vk_i), fmt_s(&s[..n])));
        vk_i += 32;
        vks.push((hex_i(vk_i), fmt_s(&s[n..])));
        vk_i += 32;
    }

    let s = hex::encode(point_to_uncompress_be(&params.cm_q_ecc.0));
    vks.push((hex_i(vk_i), fmt_s(&s[..n])));
    vk_i += 32;
    vks.push((hex_i(vk_i), fmt_s(&s[n..])));
    vk_i += 32;

    for c in params.cm_shuffle_generator_vec.iter() {
        let s = hex::encode(point_to_uncompress_be(&c.0));
        vks.push((hex_i(vk_i), fmt_s(&s[..n])));
        vk_i += 32;
        vks.push((hex_i(vk_i), fmt_s(&s[n..])));
        vk_i += 32;
    }

    // skip cm shuffle public key: 12(point) * 64 = 768
    vk_i += 768;

    let s = hex::encode(scalar_to_bytes_be(&params.anemoi_generator));
    vks.push((hex_i(vk_i), fmt_s(&s)));
    vk_i += 32;

    let s = hex::encode(scalar_to_bytes_be(&params.anemoi_generator_inv));
    vks.push((hex_i(vk_i), fmt_s(&s)));
    vk_i += 32;

    for c in params.k.iter() {
        let s = hex::encode(scalar_to_bytes_be(c));
        vks.push((hex_i(vk_i), fmt_s(&s)));
        vk_i += 32;
    }

    let s = hex::encode(scalar_to_bytes_be(&params.edwards_a));
    vks.push((hex_i(vk_i), fmt_s(&s)));
    vk_i += 32;

    let domain = FpPolynomial::<Fr>::evaluation_domain(params.cs_size).unwrap();
    let root = domain.group_gen;
    let s = hex::encode(scalar_to_bytes_be(&root));
    vks.push((hex_i(vk_i), fmt_s(&s)));
    vk_i += 32;

    // last vk is cs size
    vks.push((hex_i(vk_i), format!("{}", params.cs_size)));

    for c in params.public_vars_constraint_indices.iter() {
        let p = root.pow(&[*c as u64]);
        let s = hex::encode(scalar_to_bytes_be(&p));
        pi_poly_indices_locs.push(fmt_s(&s));
    }

    for c in params.lagrange_constants.iter() {
        let s = hex::encode(scalar_to_bytes_be(c));
        pi_poly_lagrange_locs.push(fmt_s(&s));
    }

    let mut tera = Tera::new("./*").unwrap();
    tera.add_raw_template("vke1", VKE1).unwrap();
    tera.add_raw_template("vke2", VKE2).unwrap();
    tera.add_raw_template("vk", VK).unwrap();

    let mut context = Context::new();
    context.insert("deck_num", &num);
    context.insert("pi_poly_indices_locs", &pi_poly_indices_locs);
    context.insert("pi_poly_lagrange_locs", &pi_poly_lagrange_locs);
    context.insert("vks", &vks);

    let rend_vke1 = tera.render("vke1", &context).unwrap();
    let rend_vke2 = tera.render("vke2", &context).unwrap();
    let rend_vk = tera.render("vk", &context).unwrap();

    if full {
        // generate one vk file
        let mut vk_path: PathBuf = directory.clone();
        vk_path.push(format!("VerifierKey_{}_all.sol", num));
        std::fs::write(vk_path, rend_vk + &rend_vke1 + &rend_vke2).unwrap();
    } else {
        // generate multiple vk file
        let mut vke1_path: PathBuf = directory.clone();
        vke1_path.push(format!("VerifierKeyExtra1_{}.sol", num));
        std::fs::write(vke1_path, rend_vke1).unwrap();

        let mut vke2_path: PathBuf = directory.clone();
        vke2_path.push(format!("VerifierKeyExtra2_{}.sol", num));
        std::fs::write(vke2_path, rend_vke2).unwrap();

        let mut vk_path: PathBuf = directory.clone();
        vk_path.push(format!("VerifierKey_{}.sol", num));
        std::fs::write(vk_path, rend_vk).unwrap();
    }
    println!("VerifierKey genereated directory: {:?}!", directory);
}

fn hex_i(i: i32) -> String {
    format!("0x{:x}", i)
}

fn fmt_s(s: &str) -> String {
    format!("0x{}", s)
}
