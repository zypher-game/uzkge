#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![cfg_attr(any(feature = "no_vk"), allow(unused))]

use ark_bn254::{Fr, G1Projective};
use ark_ed_on_bn254::EdwardsProjective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use zshuffle::parameters::get_shuffle_verifier_params;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Tool to generate shuffle params with card number",
    rename_all = "kebab-case"
)]
enum Actions {
    /// Generates the verifying key for shuffle
    SHUFFLE { num: usize, directory: PathBuf },

    /// Generates all necessary parameters
    ALL { directory: PathBuf },
}

fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        SHUFFLE { num, directory } => gen_shuffle_vk(num, directory, true),

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
        let (common, special) = params.split().unwrap();

        let common_ser = bincode::serialize(&common).unwrap();
        let mut common_path = directory.clone();
        common_path.push("vk-common.bin");
        save_to_file(&common_ser, common_path);

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
