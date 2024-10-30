use alloc::{slice, vec::Vec};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use uzkge::anemoi::{AnemoiJive, AnemoiJive254};

use crate::Bytes;

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __anemoi_hash(data: *const Bytes, data_len: u32, ret_val: *mut u8) -> i32 {
    let mut inputs: Vec<Fr> = Vec::new();
    for i in 0..data_len as usize {
        let bytes = unsafe { *data.wrapping_add(i) };
        let slice = bytes.to_slice();
        let input = Fr::from_be_bytes_mod_order(slice);
        inputs.push(input);
    }
    let ret = unsafe { slice::from_raw_parts_mut(ret_val, 32) };

    anemoi_hash(inputs, ret)
}

fn anemoi_hash(inputs: Vec<Fr>, ret: &mut [u8]) -> i32 {
    let res = AnemoiJive254::eval_variable_length_hash(inputs.as_slice());

    let hash = res.into_bigint().to_bytes_be();
    ret.copy_from_slice(&hash);

    hash.len() as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{vec, UniformRand};
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

    #[test]
    fn test_anemoi_hash() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let f1 = Fr::rand(&mut prng);
        let f2 = Fr::rand(&mut prng);
        let f3 = Fr::rand(&mut prng);

        let inputs = vec![f1, f2, f3];
        let mut hash1 = [0; 32];

        let res = anemoi_hash(inputs, &mut hash1);

        assert_eq!(res, 32);
    }
}
