#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![cfg_attr(any(feature = "no_vk"), allow(unused))]

use std::path::PathBuf;
use structopt::StructOpt;
use uzkge::gen_params::solidity::gen_solidity_vk;
use zshuffle::gen_params::get_shuffle_verifier_params;

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Tool to generate shuffle params with card number",
    rename_all = "kebab-case"
)]
enum Actions {
    /// Generates the verifying key for shuffle
    SHUFFLE { num: usize, directory: PathBuf },

    SOLIDITY {
        num: usize,
        directory: PathBuf,
        full: String,
    },

    /// Generates all necessary parameters
    ALL { directory: PathBuf },
}

fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        SHUFFLE { num, directory } => gen_shuffle_vk(num, directory, true),

        SOLIDITY {
            num,
            directory,
            full,
        } => {
            let params = get_shuffle_verifier_params(num).unwrap();
            gen_solidity_vk(params, num, directory, &full == "true")
        }

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
    gen_shuffle_vk(48, directory.clone(), false);
    gen_shuffle_vk(52, directory.clone(), false);
    gen_shuffle_vk(54, directory.clone(), false);
}

fn save_to_file(params_ser: &[u8], out_filename: ark_std::path::PathBuf) {
    use ark_std::io::Write;
    let filename = out_filename.to_str().unwrap();
    let mut f = ark_std::fs::File::create(&filename).expect("Unable to create file");
    f.write_all(params_ser).expect("Unable to write data");
}
