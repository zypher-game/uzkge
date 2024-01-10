// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./ShuffleVerifier.sol";

contract ShuffleService is ShuffleVerifier {
    uint256 public constant PKC_LEN = 24;

    uint256 deckNum;

    uint256[] private deck;
    uint256[] private pkc;

    constructor(address _vk1, address _vk2, uint256 _deckNum) ShuffleVerifier(_vk1, _vk2) {
        deckNum = _deckNum;
    }

    function setPkc(uint256[] calldata _pkc) public {
        require(_pkc.length == PKC_LEN, "PV02");
        pkc = _pkc;
    }

    function setDeck(uint256[] calldata _deck) public {
        require(_deck.length == deckNum * 4, "PV03");
        deck = _deck;
    }

    function verify(uint256[] calldata newDeck, bytes calldata proof) public {
        uint256 deckLength = deckNum * 4;
        require(newDeck.length == deckLength, "PV01");

        uint256[] memory pi = new uint256[](deckLength * 2);
        for (uint256 i = 0; i < deckLength; i++) {
            pi[i] = deck[i];
            pi[i + deckLength] = newDeck[i];
        }

        uint256[] memory pc = new uint256[](PKC_LEN);
        for (uint256 i = 0; i < pkc.length; i++) {
            pc[i] = pkc[i];
        }

        require(this.verifyShuffle(proof, pi, pc), "PV00");
    }
}
