use ark_ff::{BigInteger, PrimeField};
use sha3::{Digest, Keccak256};

use crate::poly_commit::pcs::ToBytes;

pub const SLOT_SIZE: usize = 32;

pub struct Transcript {
    state: Vec<u8>,
}

impl Transcript {
    pub fn new(msg: &'static [u8]) -> Self {
        let mut t = Transcript { state: Vec::new() };
        t.append_message(b"", msg);
        t
    }

    /// Append the message to the transcript. `_label` is omitted for efficiency.
    pub fn append_message(&mut self, _label: &'static [u8], msg: &[u8]) {
        if msg.len() < SLOT_SIZE {
            let mut tmp = vec![0; SLOT_SIZE];
            let index = SLOT_SIZE - msg.len();
            tmp[index..].copy_from_slice(msg);
            self.state.extend_from_slice(&tmp);
        } else {
            assert!(msg.len() % SLOT_SIZE == 0);
            self.state.extend_from_slice(msg);
        }
    }

    /// Append the u64 to the transcript. `_label` is omitted for efficiency.
    pub fn append_u64(&mut self, _label: &'static [u8], a: u64) {
        let a = a.to_be_bytes();
        let mut tmp = vec![0; SLOT_SIZE];
        let index = SLOT_SIZE - a.len();
        tmp[index..].copy_from_slice(&a);
        self.state.extend_from_slice(&tmp);
    }

    /// Append a single byte to the transcript. `_label` is omitted for efficiency.
    pub fn append_single_byte(&mut self, _label: &'static [u8], b: u8) {
        self.state.push(b);
    }

    /// Append a single commitment to the transcript.
    pub fn append_commitment<C: ToBytes>(&mut self, comm: &C) {
        Self::append_message(self, b"", &comm.to_transcript_bytes());
    }

    /// Append a challenge to the transcript.
    pub fn append_challenge<F: PrimeField>(&mut self, challenge: &F) {
        Self::append_message(self, b"", &challenge.into_bigint().to_bytes_be());
    }

    /// Generate the challenge for the current transcript,
    /// and then append it to the transcript. `_label` is omitted for
    /// efficiency.
    pub fn get_challenge_field_elem<F: PrimeField>(&mut self, _label: &'static [u8]) -> F {
        let mut hasher = Keccak256::new();
        hasher.update(&self.state);
        let mut buf = hasher.finalize();
        buf.reverse();
        let challenge = F::from_le_bytes_mod_order(&buf);

        self.state = challenge.into_bigint().to_bytes_be();

        challenge
    }
}
