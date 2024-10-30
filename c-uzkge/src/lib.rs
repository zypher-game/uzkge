#![deny(warnings, unused_crate_dependencies)]

extern crate alloc;

pub mod ed_on_bn254;

pub mod anemoi;

pub mod shuffle;

pub mod matchmaking;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes {
    pub len: u32,
    pub data: *const u8,
}

impl Bytes {
    pub fn to_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data, self.len as usize) }
    }
}
