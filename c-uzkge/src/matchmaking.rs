use core::slice;

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ethabi::Token;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use uzkge::{
    anemoi::{AnemoiJive, AnemoiJive254},
    gen_params::VerifierParams,
};
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
    verifier_params: Bytes,
    rng_seed: Bytes,
    inputs_param: *const Bytes,
    inputs_len: u32,
    committed_seed: Bytes,
    random_number: Bytes,
    ret_val: *mut u8,
    ret_len: u32,
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
    let committment = AnemoiJive254::eval_variable_length_hash(&[committed_seed]);

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
    let data = ethabi::encode(&[
        Token::Bytes(verifier_params.to_slice().to_vec()),
        Token::Array(
            inputs
                .iter()
                .map(|v| Token::Bytes(v.into_bigint().to_bytes_be()))
                .collect::<Vec<_>>(),
        ),
        Token::Array(
            outputs
                .iter()
                .map(|v| Token::Bytes(v.into_bigint().to_bytes_be()))
                .collect::<Vec<_>>(),
        ),
        Token::Bytes(committment.into_bigint().to_bytes_be()),
        Token::Bytes(random_number.into_bigint().to_bytes_be()),
        Token::Bytes(proof),
    ]);
    let len = ret_len as usize;

    if len < data.len() {
        return -6;
    }
    let ret = unsafe { slice::from_raw_parts_mut(ret_val, len) };
    ret[..data.len()].copy_from_slice(&data);
    data.len() as i32
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
    use ethabi::ParamType;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
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
        let committed_seed = Fr::rand(&mut rng).into_bigint().to_bytes_be();
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
        let mut ret = [0u8; 20480];
        let res = __generate_matchmaking_proof(
            Bytes {
                len: verifier_params.len() as u32,
                data: verifier_params.as_ptr(),
            },
            Bytes {
                len: rng_seed.len() as u32,
                data: rng_seed.as_ptr(),
            },
            inputs.as_ptr(),
            inputs.len() as u32,
            Bytes {
                len: committed_seed.len() as u32,
                data: committed_seed.as_ptr(),
            },
            Bytes {
                len: random_number.len() as u32,
                data: random_number.as_ptr(),
            },
            ret.as_mut_ptr(),
            ret.len() as u32,
        );
        assert!(res > 0, "res = {}", res);
        let data = ret[..res as usize].to_vec();

        let tokens = ethabi::decode(
            &[
                ParamType::Bytes,
                ParamType::Array(Box::new(ParamType::Bytes)),
                ParamType::Array(Box::new(ParamType::Bytes)),
                ParamType::Bytes,
                ParamType::Bytes,
                ParamType::Bytes,
            ],
            &data,
        )
        .unwrap();
        let verifier_params = tokens.first().unwrap().clone().into_bytes().unwrap();

        let input_bytes = tokens
            .get(1)
            .unwrap()
            .clone()
            .into_array()
            .unwrap()
            .iter()
            .map(|v| v.clone().into_bytes().unwrap())
            .collect::<Vec<_>>();

        let mut inputs = Vec::new();
        for it in input_bytes.iter() {
            inputs.push(Bytes {
                len: it.len() as u32,
                data: it.as_ptr(),
            })
        }
        let output_bytes = tokens
            .get(2)
            .unwrap()
            .clone()
            .into_array()
            .unwrap()
            .iter()
            .map(|v| v.clone().into_bytes().unwrap())
            .collect::<Vec<_>>();

        let mut outputs = Vec::new();
        for it in output_bytes.iter() {
            outputs.push(Bytes {
                len: it.len() as u32,
                data: it.as_ptr(),
            })
        }

        let committment = tokens.get(3).unwrap().clone().into_bytes().unwrap();
        let random_number = tokens.get(4).unwrap().clone().into_bytes().unwrap();
        let proof = tokens.get(5).unwrap().clone().into_bytes().unwrap();

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
                len: proof.len() as u32,
                data: proof.as_ptr(),
            },
        );
        assert_eq!(res, 0);
    }
}
