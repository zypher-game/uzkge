// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

library VerifierKey_20 {
    function load(uint256 vk, uint256 pi) internal pure {
        assembly {
            // The commitments of the selectors (8).
            mstore(add(vk, 0x0), 0x13b5e61805d5bbf40a999d4e8d1ae70cb96a36a7d7d88a1c39a79f4bd9148eea)
            mstore(add(vk, 0x20), 0x2ac2ba68e291bb40dbabb15636366b390a498265d75f3191ec16b5068e4bc1b5)
            mstore(add(vk, 0x40), 0x254d5975d680bdbf0535012170f11dffae10a648091f2d222f0d042801c9eb77)
            mstore(add(vk, 0x60), 0x15ef63c63d6d12958ee3cc64ff0bdf8060dc12e15a3aed51250f7c844aee154d)
            mstore(add(vk, 0x80), 0x21c3ecb6cd2413b23f683dc0072f7b7a7cf2b66692031c2cf2d9b9d03ca72dbf)
            mstore(add(vk, 0xa0), 0x2a120c052934a46a3e529b92e04155a70b3b3767a03fbe20e2c483c581486fa5)
            mstore(add(vk, 0xc0), 0x2338558704b09ad96399dd11a1cdc9b292378eaadb7d96ac1d1d13e0f942bdda)
            mstore(add(vk, 0xe0), 0x289f97e0c47111b4e2f0db2cc4c9c9e58f0f4a94faa026aeee3793768efb306e)
            mstore(add(vk, 0x100), 0x05b1bdd9c45d47b93a670c228d950918d094ad8f628e6f8c4c3f509e542b6d7f)
            mstore(add(vk, 0x120), 0x010867defb0f42fa33be74892f4013796195b8dc768e1aa2074189c47d5942b1)
            mstore(add(vk, 0x140), 0x05b1bdd9c45d47b93a670c228d950918d094ad8f628e6f8c4c3f509e542b6d7f)
            mstore(add(vk, 0x160), 0x010867defb0f42fa33be74892f4013796195b8dc768e1aa2074189c47d5942b1)
            mstore(add(vk, 0x180), 0x2211f2fcf72c9682271dc6726e7f854811cfe6a87282932f637b0b2a513395c6)
            mstore(add(vk, 0x1a0), 0x1fe594ee7ce38aac5890fb70d2a6d913ad4707ca534b5d7a7fd9167194c246fc)
            mstore(add(vk, 0x1c0), 0x2fba14bc6d29ee1fd4c83ac1c40f2f0affdfe297376eb307d1bbeb1559284ffc)
            mstore(add(vk, 0x1e0), 0x0e42f7b0fe5e1992c371f9cdc886f2912080bc0fce3db3799f9b9c13e1e035b8)

            // The commitments of perm1, perm2, ..., perm_{n_wires_per_gate}.
            mstore(add(vk, 0x200), 0x080e633e67df3593c1bf695dac59a2a95dfaee394396052aa6f6061dad99b347)
            mstore(add(vk, 0x220), 0x0bb7c4f7e3c81a2b87f98c863052dcf988313a9ca1495fc54f6b9f87fb469e86)
            mstore(add(vk, 0x240), 0x03d7eb3b93d77009247d1f93bbd2798dc5af834c9cbebcec2853d0d011d6f54e)
            mstore(add(vk, 0x260), 0x206c5f4c848a9042a65ec945ac56249a8cf9550a0e57b0a744276acdd1d461af)
            mstore(add(vk, 0x280), 0x232460896fa3155d6c7a409f90e11a9e8a6637a8991120f2512d0687d34740c4)
            mstore(add(vk, 0x2a0), 0x00c31fe6ba11ef5c18a1befc64534dc5104886b1fcb848410e2e5c1146c8914f)
            mstore(add(vk, 0x2c0), 0x04f04f66cc07bdf391e1c60a329d9fc037481d91510e375233dd0a73b1f447db)
            mstore(add(vk, 0x2e0), 0x12116a1f867bdb640293128da9910c966a5c79ba8d23e93d4dc934e299993f39)
            mstore(add(vk, 0x300), 0x182e5904f68263a3bbe83512e33b62ab81d92c1efaf03e25d39d9fff81b60a35)
            mstore(add(vk, 0x320), 0x22a2ab3bd7473030e9c81ba661b276c10712cb5af18b0ec224e207a7daebc3b9)

            // The commitment of the boolean selector.
            mstore(add(vk, 0x340), 0x2a3552215e1642082588f682e9faa317c08851ec45d28f05d4868e4ef746bb9d)
            mstore(add(vk, 0x360), 0x013aa92a8efb15f879e4d1a0ef686226f89f32d50b5df9105ee9573693352bb7)

            // The commitments of the preprocessed round key selectors.
            mstore(add(vk, 0x380), 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(add(vk, 0x3a0), 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(add(vk, 0x3c0), 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(add(vk, 0x3e0), 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(add(vk, 0x400), 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(add(vk, 0x420), 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(add(vk, 0x440), 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(add(vk, 0x460), 0x0000000000000000000000000000000000000000000000000000000000000000)

            // The commitment of the ecc selector.
            mstore(add(vk, 0x480), 0x1135c7377f75d0dcc677da46a7d1daf5c07cd1200c0de4ef072bc6dbc4d4459d)
            mstore(add(vk, 0x4a0), 0x21a00c09aa939ab2e531ff9468899515e4f66d5fadf55bd11f3bb7ad6df4af31)

            // The commitments of the shuffle generator selectors.
            mstore(add(vk, 0x4c0), 0x25bde92c518fcab5575072fb3ef0d9f35aef52a529cb4bb4d9d7cde56f8ed6d7)
            mstore(add(vk, 0x4e0), 0x0399c72ed68520ffc282da59e8911e92fa907f9e8113b0386167269200de1d63)
            mstore(add(vk, 0x500), 0x15156c29e5651a04c60ffae60f4ca92635f347b415f380046f96fce7b9e985bb)
            mstore(add(vk, 0x520), 0x2b88848295d6dc228bbb1f703df8f1ebfb4343114b69b407d131d521b02e40c0)
            mstore(add(vk, 0x540), 0x1ee65f5f9dc91fdd5423722e2e5879822cd37353480a691025710d1cdd10d6b0)
            mstore(add(vk, 0x560), 0x01085d0ce87a0493720f8ad1168af18776d2962d896bdaa20085511591bce770)
            mstore(add(vk, 0x580), 0x2314c3b6d169b89f2d5bb4a5df77d8c8173ffb2c70ec5dc7f640825943819b73)
            mstore(add(vk, 0x5a0), 0x13f20518ab13a30b22ba1364e4853c39f7cc026c8184ecc03024a56848121b2d)
            mstore(add(vk, 0x5c0), 0x08629513703963bcb5fd13d212827c345772a0abbb375eea651423bbe0937ffe)
            mstore(add(vk, 0x5e0), 0x0bae83b1168b35086890e01381742dbce1aa03e8a78ae857d1eeaabc9092f1e0)
            mstore(add(vk, 0x600), 0x1d842e80c98bb25520b3340090c47fe865b72f36febe14c9ffb8098c15f972a3)
            mstore(add(vk, 0x620), 0x089c5331b473880f79d8c620f56c4d8f56a90b93ff9d866dc6c1214b46e88e2f)
            mstore(add(vk, 0x640), 0x1e4817d592d9a84ce38fec9aca102f2547714ca22dd22d03ea1ea5562e933fb1)
            mstore(add(vk, 0x660), 0x3020447a26a64250bf17b4fe4e288c2bf94091d065c983418d4fe4f0dd21d5a2)
            mstore(add(vk, 0x680), 0x0d8e555dbf81463279d4125c6c862c0a753d76113221bed3166e8e8eaf0498ef)
            mstore(add(vk, 0x6a0), 0x18cf7911ddd2ac1b254cb3a6435de42a318a45470a580dbae84cb9fa24ffd4d9)
            mstore(add(vk, 0x6c0), 0x18b1ce4b8f61476e70afd2259f8f35ec18e0170c353592ad735f0176cbda55a9)
            mstore(add(vk, 0x6e0), 0x1ef5569839301446d276b66507dcdbda41d58dc0353587b5742591d4ab9de523)
            mstore(add(vk, 0x700), 0x2b467c2521b21c0c05493cdb8320445b2c7e9ddae43f92adf7833a34a764eaad)
            mstore(add(vk, 0x720), 0x2425ebd93df694c046af1fc24f53fa8435501cc0e25dd24ccd5966ffa3e25978)
            mstore(add(vk, 0x740), 0x12c932e4c9fece70d76f0a4459362f9229dfc05b247e105b8fd541720f7e6c90)
            mstore(add(vk, 0x760), 0x059595fa5350a4482ef005bffafc8cacd7b9fdd66397d3752c0e6fe85295656a)
            mstore(add(vk, 0x780), 0x1ee88db8d29f8ffcd4095cffc04479b6c6049f4f7b9840f649d93e9f74b47a1c)
            mstore(add(vk, 0x7a0), 0x147b9aa28a30aaf30168d29011ef532e45ff53d76c228020f9a5982cae7c71d3)

            // The Anemoi generator.
            mstore(add(vk, 0xac0), 0x0000000000000000000000000000000000000000000000000000000000000000)

            // The Anemoi generator's inverse.
            mstore(add(vk, 0xae0), 0x0000000000000000000000000000000000000000000000000000000000000000)

            // `n_wires_per_gate` different quadratic non-residue in F_q-{0}.
            mstore(add(vk, 0xb00), 0x0000000000000000000000000000000000000000000000000000000000000001)
            mstore(add(vk, 0xb20), 0x2f8dd1f1a7583c42c4e12a44e110404c73ca6c94813f85835da4fb7bb1301d4a)
            mstore(add(vk, 0xb40), 0x2042a587a90c187b0a087c03e29c968b950b1db26d5c82d666905a6895790c0a)
            mstore(add(vk, 0xb60), 0x2db4944e13e6e33cf0ef0734796ff332d73b5fa160dca733bf529e9b758e4960)
            mstore(add(vk, 0xb80), 0x1d9e3a4aaf01052d9925138dc6d7d05aa614e311040142458b045d0053d22f46)

            // The edwards a.
            mstore(add(vk, 0xba0), 0x0000000000000000000000000000000000000000000000000000000000000001)

            // The domain's group generator with csSize.
            mstore(add(vk, 0xbc0), 0x0931d596de2fd10f01ddd073fd5a90a976f169c76f039bb91c4775720042d43a)

            // The size of constraint system.
            mstore(add(vk, 0xbe0), 4096)

            /// public inputs length
            mstore(add(pi, 0x0), 160)
        }
    }
}
