#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![cfg_attr(any(feature = "no_vk"), allow(unused))]

use ark_bn254::{Fr, G1Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use zmatchmaking::gen_params::get_verifier_params;

#[derive(StructOpt, Debug)]
#[structopt(about = "Tool to generate verifier params", rename_all = "kebab-case")]
enum Actions {
    /// Generates the verifying key
    MATCHMAKING { directory: PathBuf },
}

fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        MATCHMAKING { directory } => gen_vk_specific(directory),
    };
}

// cargo run --release --features="gen no_vk" --bin gen-params matchmaking "./parameters"
fn gen_vk_specific(directory: PathBuf) {
    let params = get_verifier_params().unwrap();
    println!(
        "the size of the constraint system of shuffle: {}",
        params.shrunk_cs.size
    );

    let (_, special) = params.split().unwrap();
    let specials_ser = bincode::serialize(&special).unwrap();
    let mut specials_path: PathBuf = directory.clone();
    specials_path.push("vk-specific.bin");
    save_to_file(&specials_ser, specials_path);
}

fn save_to_file(params_ser: &[u8], out_filename: ark_std::path::PathBuf) {
    use ark_std::io::Write;
    let filename = out_filename.to_str().unwrap();
    let mut f = ark_std::fs::File::create(&filename).expect("Unable to create file");
    f.write_all(params_ser).expect("Unable to write data");
}
