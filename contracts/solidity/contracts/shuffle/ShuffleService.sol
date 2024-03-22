// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./ShuffleVerifier.sol";
import "./VerifierKey_20.sol";
import "./VerifierKey_52.sol";

contract ShuffleService is ShuffleVerifier {
    uint256 public constant PKC_LEN = 24;

    uint256 deckNum;

    uint256[] private deck;
    uint256[] private pkc;

    constructor(address _vk1, address _vk2, uint256 _deckNum) ShuffleVerifier(_vk1, _vk2) {
        deckNum = _deckNum;
    }

    function setPkc(uint256[] calldata _pkc) public {
        require(_pkc.length == PKC_LEN, "SS02");
        pkc = _pkc;
    }

    function setDeck(uint256[] calldata _deck) public {
        require(_deck.length == deckNum * 4, "SS03");
        deck = _deck;
    }

    function verify(uint256[] calldata newDeck, bytes calldata proof) public {
        uint256 deckLength = deckNum * 4;
        require(newDeck.length == deckLength, "SS01");

        uint256[] memory pi = new uint256[](deckLength * 2);
        for (uint256 i = 0; i < deckLength; i++) {
            pi[i] = deck[i];
            pi[i + deckLength] = newDeck[i];
        }

        uint256[] memory pc = new uint256[](PKC_LEN);
        for (uint256 i = 0; i < pkc.length; i++) {
            pc[i] = pkc[i];
        }

        if (deckNum == 20) {
            _verifyKey = VerifierKey_20.load;
        } else if (deckNum == 52) {
            _verifyKey = VerifierKey_52.load;
        } else {
            revert("SS04");
        }

        require(this.verifyShuffle(proof, pi, pc), "SS00");
    }
}
