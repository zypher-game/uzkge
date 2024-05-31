use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use core::slice;

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __point_add(
    x1: *const u8,
    y1: *const u8,
    x2: *const u8,
    y2: *const u8,
    ret_val: *mut u8,
) -> i32 {
    let x1 = unsafe { slice::from_raw_parts(x1, 32) };
    let x_1 = Fq::from_be_bytes_mod_order(x1);

    let y1 = unsafe { slice::from_raw_parts(y1, 32) };
    let y_1 = Fq::from_be_bytes_mod_order(y1);

    let x2 = unsafe { slice::from_raw_parts(x2, 32) };
    let x_2 = Fq::from_be_bytes_mod_order(x2);

    let y2 = unsafe { slice::from_raw_parts(y2, 32) };
    let y_2 = Fq::from_be_bytes_mod_order(y2);

    let ret = unsafe { slice::from_raw_parts_mut(ret_val, 64) };

    point_add(x_1, y_1, x_2, y_2, ret)
}

fn point_add(x_1: Fq, y_1: Fq, x_2: Fq, y_2: Fq, ret: &mut [u8]) -> i32 {
    let p1 = EdwardsAffine::new(x_1, y_1);
    let p2 = EdwardsAffine::new(x_2, y_2);
    let p3 = p1 + p2;

    match p3.into_affine().xy() {
        Some((r_x, r_y)) => {
            ret[0..32].copy_from_slice(&r_x.into_bigint().to_bytes_be());
            ret[32..64].copy_from_slice(&r_y.into_bigint().to_bytes_be());
            ret.len() as i32
        }
        None => -1,
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __scalar_mul(s: *const u8, x: *const u8, y: *const u8, ret_val: *mut u8) -> i32 {
    let s = unsafe { slice::from_raw_parts(s, 32) };
    let s = Fr::from_be_bytes_mod_order(s);

    let x = unsafe { slice::from_raw_parts(x, 32) };
    let x = Fq::from_be_bytes_mod_order(x);

    let y = unsafe { slice::from_raw_parts(y, 32) };
    let y = Fq::from_be_bytes_mod_order(y);

    let ret = unsafe { slice::from_raw_parts_mut(ret_val, 64) };

    scalar_mul(s, x, y, ret)
}

fn scalar_mul(s: Fr, x: Fq, y: Fq, ret: &mut [u8]) -> i32 {
    let p = EdwardsAffine::new(x, y);
    let p2 = p * s;

    match p2.into_affine().xy() {
        Some((r_x, r_y)) => {
            ret[0..32].copy_from_slice(&r_x.into_bigint().to_bytes_be());
            ret[32..64].copy_from_slice(&r_y.into_bigint().to_bytes_be());
            ret.len() as i32
        }
        None => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{vec, UniformRand};
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

    #[test]
    fn test_point_add() {
        // generate p1, p2
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let p1 = EdwardsAffine::rand(&mut prng);
        let p2 = EdwardsAffine::rand(&mut prng);
        let (p1_0, p1_1) = p1.xy().unwrap();
        let (p2_0, p2_1) = p2.xy().unwrap();

        // add with rust
        let (p3_0, p3_1) = (p1 + p2)
            .into_affine()
            .xy()
            .map(|(x, y)| (x.into_bigint().to_bytes_be(), y.into_bigint().to_bytes_be()))
            .unwrap();

        let mut ret = vec![0u8; 64];

        let res = point_add(p1_0, p1_1, p2_0, p2_1, &mut ret);

        assert_eq!(res, 64);

        assert_eq!(ret[..32].to_vec(), p3_0);
        assert_eq!(ret[32..].to_vec(), p3_1);
    }

    #[test]
    fn test_scalar_mul() {
        // generate scalar, p1
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let s = Fr::rand(&mut prng);
        let p1 = EdwardsAffine::rand(&mut prng);
        let (p1_0, p1_1) = p1.xy().unwrap();

        // add with rust
        let (p3_0, p3_1) = (p1 * s)
            .into_affine()
            .xy()
            .map(|(x, y)| (x.into_bigint().to_bytes_be(), y.into_bigint().to_bytes_be()))
            .unwrap();

        let mut ret = vec![0u8; 64];

        let res = scalar_mul(s, p1_0, p1_1, &mut ret);
        assert_eq!(res, 64);

        assert_eq!(ret[..32].to_vec(), p3_0);
        assert_eq!(ret[32..].to_vec(), p3_1);
    }
}
