<!-- [![crate](https://img.shields.io/badge/crates.io-v0.1.0-green.svg)](https://crates.io/crates/zshuffle) [![doc](https://img.shields.io/badge/docs.rs-v0.1.0-blue.svg)](https://docs.rs/zshuffle) -->

# zshuffle
Encrypt and shuffle cards, resulting in a randomly ordered deck

## Contents
- [wasm](./wasm) SDK for JavaScript
- Generate player accounts (BabyJubjub keypairs) & aggregate their public keys to form a joint key.
- Initialize the deck according to the number of cards
- Mask & verify the deck with joint key
- Shuffle & verify the deck with joint key
- Reveal & unmask cards

## Running the example
This is a simple example implementing the mental poker protocol. It shows how to encrypt and shuffle cards, just run:
```text
 cargo test --release --package zshuffle --lib -- tests::test_poker
```

## License

This project is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html).
