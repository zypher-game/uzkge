pub mod serialization;

pub mod transcript;

pub mod errors;

pub mod prelude;

/// Shift a big integer (represented as a little-endian bytes vector) by one bit.
pub fn shift_u8_vec(r: &mut Vec<u8>) {
    let mut next = 0u8;
    for e in r.iter_mut().rev() {
        let prev = *e;
        *e = (*e >> 1) | next;
        next = (prev % 2) << 7;
    }
    if *r.last().unwrap() == 0 && r.len() > 1 {
        r.pop();
    }
}

/// Convert a u64 slice from a shrink bytes (little-endian)
pub fn u64_limbs_from_bytes(slice: &[u8]) -> Vec<u64> {
    let mut r: Vec<u64> = vec![];
    let n = slice.len() / 8;
    for i in 0..n {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(&slice[i * 8..(i + 1) * 8]);
        r.push(u64::from_le_bytes(u64_bytes));
    }
    if slice.len() % 8 != 0 {
        let bytes = &slice[n * 8..];
        let mut u64_bytes = [0u8; 8];
        u64_bytes[..bytes.len()].copy_from_slice(bytes);
        r.push(u64::from_le_bytes(u64_bytes));
    }
    r
}
