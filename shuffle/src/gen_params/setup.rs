#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![cfg_attr(any(feature = "no_vk"), allow(unused))]

use ark_bn254::{Fr, G1Projective};
use ark_ed_on_bn254::EdwardsProjective;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use tera::{Context, Tera};
use zplonk::{
    poly_commit::field_polynomial::FpPolynomial, utils::serialization::scalar_to_bytes_be,
};
use zshuffle::gen_params::get_shuffle_verifier_params;

const SVK1: &str = include_str!("../../parameters/ShuffleVerifierKey1.sol");
const SVK2: &str = include_str!("../../parameters/ShuffleVerifierKey2.sol");
const VK: &str = include_str!("../../parameters/VerifierKey.sol");

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Tool to generate shuffle params with card number",
    rename_all = "kebab-case"
)]
enum Actions {
    /// Generates the verifying key for shuffle
    SHUFFLE {
        num: usize,
        directory: PathBuf,
    },

    SOLIDITY {
        num: usize,
        directory: PathBuf,
    },

    /// Generates all necessary parameters
    ALL {
        directory: PathBuf,
    },
}

fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        SHUFFLE { num, directory } => gen_shuffle_vk(num, directory, true),

        SOLIDITY { num, directory } => gen_solidity_vk(num, directory, true),

        ALL { directory } => gen_all(directory),
    };
}

// cargo run --release --features="gen no_vk" --bin gen-params shuffle 52 "./parameters"
fn gen_shuffle_vk(num: usize, directory: PathBuf, full: bool) {
    let params = get_shuffle_verifier_params(num).unwrap();
    println!(
        "the size of the constraint system of shuffle: {}",
        params.shrunk_cs.size
    );

    if full {
        // generate one vk file
        let full_ser = bincode::serialize(&params).unwrap();
        let mut full_path = directory.clone();
        full_path.push(format!("vk-{}.bin", num));
        save_to_file(&full_ser, full_path);
    } else {
        let (_, special) = params.split().unwrap();
        let specials_ser = bincode::serialize(&special).unwrap();
        let mut specials_path: PathBuf = directory.clone();
        specials_path.push(format!("vk-specific-{}.bin", num));
        save_to_file(&specials_ser, specials_path);
    }
}

// cargo run --release --features="gen no_vk" --bin gen-params all "./parameters"
fn gen_all(directory: PathBuf) {
    gen_shuffle_vk(52, directory.clone(), false);
    gen_shuffle_vk(54, directory.clone(), false);
}

fn save_to_file(params_ser: &[u8], out_filename: ark_std::path::PathBuf) {
    use ark_std::io::Write;
    let filename = out_filename.to_str().unwrap();
    let mut f = ark_std::fs::File::create(&filename).expect("Unable to create file");
    f.write_all(params_ser).expect("Unable to write data");
}

fn gen_solidity_vk(num: usize, directory: PathBuf, full: bool) {
    let params = get_shuffle_verifier_params(num).unwrap().verifier_params;
    println!(
        "the size of the constraint system of shuffle: {}",
        params.cs_size
    );

    let domain = FpPolynomial::<Fr>::evaluation_domain(params.cs_size).unwrap();
    let root = domain.group_gen;
    let s = hex::encode(scalar_to_bytes_be(&root));

    let mut pi_poly_indices_locs = vec![];
    for (i, c) in params.public_vars_constraint_indices.iter().enumerate() {
        let p = root.pow(&[*c as u64]);
        let s = hex::encode(scalar_to_bytes_be(&p));
        pi_poly_indices_locs.push(format!("0x{}", s));
    }

    let mut pi_poly_lagrange_locs = vec![];
    for (i, c) in params.lagrange_constants.iter().enumerate() {
        let s = hex::encode(scalar_to_bytes_be(c));
        pi_poly_lagrange_locs.push(format!("0x{}", s));
    }

    let mut tera = Tera::new("./*").unwrap();
    tera.add_raw_template("svk1", SVK1).unwrap();
    tera.add_raw_template("svk2", SVK2).unwrap();

    let mut context = Context::new();
    context.insert("deck_num", &num);
    context.insert("pi_poly_indices_locs", &pi_poly_indices_locs);
    context.insert("pi_poly_lagrange_locs", &pi_poly_lagrange_locs);

    let rendered_svk1 = tera.render("svk1", &context).unwrap();
    let rendered_svk2 = tera.render("svk2", &context).unwrap();

    let extra_key1 = ();
    let extra_key2 = ();
    let verifier_key = ();

    let mut svk1_path: PathBuf = directory.clone();
    svk1_path.push(format!("ShuffleVerifierKey1_{}.sol", num));
    std::fs::write(svk1_path, rendered_svk1).unwrap();

    let mut svk2_path: PathBuf = directory.clone();
    svk2_path.push(format!("ShuffleVerifierKey2_{}.sol", num));
    std::fs::write(svk2_path, rendered_svk2).unwrap();

    if full {
        // generate one vk file
    } else {
        // generate multiple vk file
    }
}
