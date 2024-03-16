// SPDX-License-Identifier: UNLICENSED
// Generated file from uzkge/gen-params, DONOT edit!
pragma solidity ^0.8.20;

library VerifierKey_{{ deck_num }} {
    function load(uint256 vk, uint256 pi) internal pure {
        assembly {
            // verifier key
            {% for p in vks %}mstore(add(vk, {{ p.0 }}), {{ p.1 }})
            {% endfor %}
            /// public inputs length
            mstore(add(pi, 0x0), {{ deck_num * 8 }})
        }
    }
}
