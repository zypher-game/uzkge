#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![cfg_attr(any(feature = "no_srs", feature = "no_vk"), allow(unused))]

use ark_bn254::{Fr, G1Projective};
use ark_ed_on_bn254::EdwardsProjective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, path::PathBuf};
use structopt::StructOpt;
use zplonk::parameters::{VerifierParams, SRS};
use zplonk::poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Tool to generate necessary zero-knowledge proof parameters.",
    rename_all = "kebab-case"
)]
enum Actions {
    /// Generates the verifying key for shuffle
    SHUFFLE { directory: PathBuf },

    /// Cut the SRS, adapt to Lagrange, and only save the minimum 2^11, 2^12, and 2^13 padding
    CUT_SRS { directory: PathBuf },

    /// Generates all necessary parameters
    ALL { directory: PathBuf },
}

fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        SHUFFLE { directory } => gen_shuffle_vk(directory),

        CUT_SRS { directory } => cut_srs(directory),

        ALL { directory } => gen_all(directory),
    };
}

// cargo run --release --features="gen no_vk" --bin gen-params shuffle "./parameters"
fn gen_shuffle_vk(directory: PathBuf) {
    let params = VerifierParams::get_shuffle().unwrap();
    println!(
        "the size of the constraint system of shuffle: {}",
        params.shrunk_cs.size
    );

    let (common, special) = params.split().unwrap();

    let common_ser = bincode::serialize(&common).unwrap();
    let mut common_path = directory.clone();
    common_path.push("vk-common.bin");
    save_to_file(&common_ser, common_path);

    let specials_ser = bincode::serialize(&special).unwrap();
    let mut specials_path: PathBuf = directory.clone();
    specials_path.push("vk-specific.bin");
    save_to_file(&specials_ser, specials_path);
}

// cargo run --release --features="gen no_vk" --bin gen-params cut-srs "./parameters"
fn cut_srs(mut path: PathBuf) {
    let srs = SRS.unwrap();
    let KZGCommitmentSchemeBN254 {
        public_parameter_group_1,
        public_parameter_group_2,
    } = KZGCommitmentSchemeBN254::from_unchecked_bytes(&srs).unwrap();

    if public_parameter_group_1.len() == 2060 {
        println!("Already complete");
        return;
    }

    let mut new_group_1 = vec![G1Projective::default(); 2060];
    new_group_1[0..2051].copy_from_slice(&public_parameter_group_1[0..2051]);
    new_group_1[2051..2054].copy_from_slice(&public_parameter_group_1[4096..4099]);
    new_group_1[2054..2057].copy_from_slice(&public_parameter_group_1[8192..8195]);
    new_group_1[2057..2060].copy_from_slice(&public_parameter_group_1[16384..16387]);

    let new_srs = KZGCommitmentSchemeBN254 {
        public_parameter_group_2,
        public_parameter_group_1: new_group_1,
    };

    let bytes = new_srs.to_unchecked_bytes().unwrap();
    path.push("srs-padding.bin");
    save_to_file(&bytes, path);
}

// cargo run --release --features="gen no_vk" --bin gen-params all "./parameters"
fn gen_all(directory: PathBuf) {
    gen_shuffle_vk(directory.clone());
    cut_srs(directory)
}

fn save_to_file(params_ser: &[u8], out_filename: ark_std::path::PathBuf) {
    use ark_std::io::Write;
    let filename = out_filename.to_str().unwrap();
    let mut f = ark_std::fs::File::create(&filename).expect("Unable to create file");
    f.write_all(params_ser).expect("Unable to write data");
}
