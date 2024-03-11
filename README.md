# uzkge
Universal Zero Knowledge Game Engine

## Components
- [zplonk](./plonk): App-specific PlonK with various gadgets & primitives
- [zshuffle](./shuffle): Encrypt and shuffle cards, resulting in a randomly ordered deck
- [zmatchmaking](./matchmaking): Mathmaking for PvP games with provable fairness and randomness
- [verifier (solidity)](./contracts/solidity): Common verifiers for all EVM chains

<!-- ## Documents -->
<!-- - [Online - coming soon]() or [Source Code](https://github.com/zypher-game/docs) -->

## Requirements

This project is under development and is already being used in games by the community.

We are using the latest main branch of arkworks, so please use patch to change dependencies
```
[patch.crates-io]
ark-ff = { git = "https://github.com/arkworks-rs/algebra" }
ark-ec = { git = "https://github.com/arkworks-rs/algebra" }
ark-poly = { git = "https://github.com/arkworks-rs/algebra" }
ark-serialize = { git = "https://github.com/arkworks-rs/algebra" }
ark-bn254 = { git = "https://github.com/arkworks-rs/algebra" }
ark-ed-on-bn254 = { git = "https://github.com/arkworks-rs/algebra" }
```

## License

This project is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html).
