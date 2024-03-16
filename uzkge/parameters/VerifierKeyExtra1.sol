// SPDX-License-Identifier: UNLICENSED
// Generated file from uzkge/gen-params, DONOT edit!
pragma solidity ^0.8.20;

contract VerifierKeyExtra1_{{ deck_num }} {
    uint256[{{ deck_num * 8 }}] public PI_POLY_INDICES_LOC;

    constructor() {
        // The public constrain variables indices.
        {% for p in pi_poly_indices_locs %}PI_POLY_INDICES_LOC[{{ loop.index - 1 }}] = {{ p }};
        {% endfor %}
    }
}
