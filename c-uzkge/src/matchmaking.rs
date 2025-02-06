use core::slice;

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use uzkge::gen_params::VerifierParams;
use zmatchmaking::{
    build_cs::{prove_matchmaking, verify_matchmaking, Proof},
    gen_params::{gen_prover_params, get_verifier_params},
};

use crate::Bytes;
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __verifier_matchmaking_params(ret_val: *mut u8, ret_len: u32) -> i32 {
    let param = match get_verifier_params() {
        Ok(v) => v,
        Err(_) => return -1,
    };

    match bincode::serialize(&param) {
        Ok(v) => {
            let len = ret_len as usize;

            if len < v.len() {
                return -3;
            }
            let ret = unsafe { slice::from_raw_parts_mut(ret_val, len) };

            ret[..v.len()].copy_from_slice(&v);
            v.len() as i32
        }
        Err(_) => -2,
    }
}
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __generate_matchmaking_proof(
    rng_seed: Bytes,
    inputs_param: *const Bytes,
    inputs_len: u32,
    committed_seed: Bytes,
    random_number: Bytes,
    out_outputs: *mut u8,
    out_outputs_len: *mut u32,
    out_proof: *mut u8,
    out_proof_len: *mut u32,
) -> i32 {
    let inputs = {
        let mut inputs = Vec::new();
        for i in 0..inputs_len as usize {
            let data = unsafe { *inputs_param.wrapping_add(i) };
            let slice = data.to_slice();
            let input = Fr::from_be_bytes_mod_order(slice);
            inputs.push(input);
        }
        inputs
    };

    let seed = match rng_seed.to_slice().try_into() {
        Ok(v) => v,
        Err(_e) => return -2,
    };

    let mut rng = ChaChaRng::from_seed(seed);

    let committed_seed = {
        let data = committed_seed.to_slice();
        Fr::from_be_bytes_mod_order(data)
    };

    let random_number = {
        let data = random_number.to_slice();
        Fr::from_be_bytes_mod_order(data)
    };

    let (proof, outputs) = match prove_matchmaking(
        &mut rng,
        &inputs,
        &committed_seed,
        &random_number,
        &match gen_prover_params() {
            Ok(v) => v,
            Err(_) => return -3,
        },
    ) {
        Ok(v) => v,
        Err(_) => return -4,
    };

    let proof = match bincode::serialize(&proof) {
        Ok(v) => v,
        Err(_) => return -5,
    };

    if unsafe { *out_outputs_len } < outputs.len() as u32 {
        return -6;
    }

    let out_outputs =
        unsafe { slice::from_raw_parts_mut(out_outputs, ((*out_outputs_len) * 32) as usize) };
    for (index, output) in outputs.iter().enumerate() {
        let byte = output.into_bigint().to_bytes_be();
        out_outputs[index * 32..(index + 1) * 32].copy_from_slice(&byte);
    }
    unsafe { *out_outputs_len = outputs.len() as u32 };

    if unsafe { *out_proof_len } < proof.len() as u32 {
        return -7;
    }
    let out_proof = unsafe { slice::from_raw_parts_mut(out_proof, (*out_proof_len) as usize) };
    unsafe { *out_proof_len = proof.len() as u32 };
    out_proof[..proof.len()].copy_from_slice(&proof);

    0
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __verify_matchmaking(
    verifier_params: Bytes,
    inputs_param: *const Bytes,
    inputs_len: u32,
    outputs_param: *const Bytes,
    outputs_len: u32,
    commitment: Bytes,
    random_number: Bytes,
    proof: Bytes,
) -> i32 {
    let verifier_params: VerifierParams = {
        let data = verifier_params.to_slice();
        match bincode::deserialize(data) {
            Ok(v) => v,
            Err(_e) => return -1,
        }
    };

    let inputs = {
        let mut inputs = Vec::new();
        for i in 0..inputs_len as usize {
            let data = unsafe { *inputs_param.wrapping_add(i) };
            let slice = data.to_slice();
            let input = Fr::from_be_bytes_mod_order(slice);
            inputs.push(input);
        }
        inputs
    };

    let outputs = {
        let mut outputs = Vec::new();
        for i in 0..outputs_len as usize {
            let data = unsafe { *outputs_param.wrapping_add(i) };
            let slice = data.to_slice();
            let output = Fr::from_be_bytes_mod_order(slice);
            outputs.push(output);
        }
        outputs
    };

    let commitment = {
        let data = commitment.to_slice();
        Fr::from_be_bytes_mod_order(data)
    };

    let random_number = {
        let data = random_number.to_slice();
        Fr::from_be_bytes_mod_order(data)
    };

    let proof: Proof = {
        let data = proof.to_slice();
        match bincode::deserialize(data) {
            Ok(v) => v,
            Err(_e) => return -2,
        }
    };

    match verify_matchmaking(
        &verifier_params,
        &inputs,
        &outputs,
        &commitment,
        &random_number,
        &proof,
    ) {
        Ok(_) => 0,
        Err(_e) => -3,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
    use uzkge::anemoi::{AnemoiJive, AnemoiJive254};
    use zmatchmaking::build_cs::N;

    use crate::{
        matchmaking::{__generate_matchmaking_proof, __verifier_matchmaking_params},
        Bytes,
    };

    use super::__verify_matchmaking;

    #[test]
    fn test_matchmaking() {
        let verifier_params = {
            let mut ret = [0u8; 10240];
            let res = __verifier_matchmaking_params(ret.as_mut_ptr(), ret.len() as u32);
            assert!(res > 0, "res = {}", res);
            ret[..res as usize].to_vec()
        };

        let rng_seed = [0u8; 32];

        let mut rng = ChaChaRng::from_seed(rng_seed);
        let committed_seed = Fr::rand(&mut rng);
        let committed_seed_bytes = committed_seed.into_bigint().to_bytes_be();
        let random_number = Fr::rand(&mut rng).into_bigint().to_bytes_be();

        let inputs = (1..=N)
            .into_iter()
            .map(|i| Fr::from(i as u64))
            .collect::<Vec<_>>();
        let input_bytes = inputs
            .iter()
            .map(|v| v.into_bigint().to_bytes_be())
            .collect::<Vec<_>>();
        let mut inputs = Vec::new();
        for it in input_bytes.iter() {
            inputs.push(Bytes {
                len: it.len() as u32,
                data: it.as_ptr(),
            })
        }
        let mut out_outputs = [0u8; 50 * 32];
        let mut out_outputs_len = 50;

        let mut out_proof = [0u8; 20480];
        let mut out_proof_len = out_proof.len() as u32;

        let res = __generate_matchmaking_proof(
            Bytes {
                len: rng_seed.len() as u32,
                data: rng_seed.as_ptr(),
            },
            inputs.as_ptr(),
            inputs.len() as u32,
            Bytes {
                len: committed_seed_bytes.len() as u32,
                data: committed_seed_bytes.as_ptr(),
            },
            Bytes {
                len: random_number.len() as u32,
                data: random_number.as_ptr(),
            },
            out_outputs.as_mut_ptr(),
            &mut out_outputs_len,
            out_proof.as_mut_ptr(),
            &mut out_proof_len,
        );
        assert_eq!(res, 0);

        let mut inputs = Vec::new();
        for it in input_bytes.iter() {
            inputs.push(Bytes {
                len: it.len() as u32,
                data: it.as_ptr(),
            })
        }
        let mut outputs = Vec::new();
        for it in input_bytes.iter() {
            outputs.push(Bytes {
                len: it.len() as u32,
                data: it.as_ptr(),
            })
        }

        let mut outputs = Vec::new();
        for i in 0..out_outputs_len as usize {
            outputs.push(Bytes {
                len: 32,
                data: unsafe { out_outputs.as_ptr().byte_add(i * 32) },
            })
        }

        let committment = AnemoiJive254::eval_variable_length_hash(&[committed_seed])
            .into_bigint()
            .to_bytes_be();

        let res = __verify_matchmaking(
            Bytes {
                len: verifier_params.len() as u32,
                data: verifier_params.as_ptr(),
            },
            inputs.as_ptr(),
            inputs.len() as u32,
            outputs.as_ptr(),
            outputs.len() as u32,
            Bytes {
                len: committment.len() as u32,
                data: committment.as_ptr(),
            },
            Bytes {
                len: random_number.len() as u32,
                data: random_number.as_ptr(),
            },
            Bytes {
                len: out_proof_len,
                data: out_proof.as_ptr(),
            },
        );
        assert_eq!(res, 0);
    }
}
