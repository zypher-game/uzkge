#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![cfg_attr(any(feature = "no_srs"), allow(unused))]

use ark_bn254::G1Projective;
use std::path::PathBuf;
use structopt::StructOpt;
use zplonk::{params::SRS, poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254};

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Tool to generate necessary zero-knowledge proof parameters.",
    rename_all = "kebab-case"
)]
enum Actions {
    /// Cut the SRS, adapt to Lagrange, and only save the minimum 2^11, 2^12, and 2^13 padding.
    /// The completed SRS can be generated from https://github.com/sunhuachuang/export-setup-parameters
    CUT_SRS { directory: PathBuf },

    /// Generates all necessary parameters
    ALL { directory: PathBuf },
}

fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        CUT_SRS { directory } => cut_srs(directory),

        ALL { directory } => gen_all(directory),
    };
}

// cargo run --release --features="gen" --bin gen-params cut-srs "./parameters"
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

// cargo run --release --features="gen" --bin gen-params all "./parameters"
fn gen_all(directory: PathBuf) {
    cut_srs(directory)
}

fn save_to_file(params_ser: &[u8], out_filename: ark_std::path::PathBuf) {
    use ark_std::io::Write;
    let filename = out_filename.to_str().unwrap();
    let mut f = ark_std::fs::File::create(&filename).expect("Unable to create file");
    f.write_all(params_ser).expect("Unable to write data");
}
