// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./ShuffleVerifier.sol";
import "./VerifierKey_52.sol";

contract ShuffleService is ShuffleVerifier {
    // Only save the first 17 cards.
    uint256[] private deck;
    uint256[] private pkc;

    uint256 deckDigest;
    uint256 deckNum;

    event NewCardDeck(uint256 gameId, uint256 index, uint256 card);

    constructor(address _vk1, address _vk2, uint256 _deckNum) ShuffleVerifier(_vk1, _vk2) {
        require(_deckNum > 16, "SS05");
        deckNum = _deckNum;
    }

    function setDeckAndDigest(uint256[] calldata _deck, uint256 _deckDigest) public {
        require(_deck.length == 68, "SS03"); // 17 cards
        deck = _deck;
        deckDigest = _deckDigest;
    }

    function setPkc(uint256[] calldata _pkc) public {
        require(_pkc.length == 24, "SS02");
        pkc = _pkc;
    }

    function verify(uint256[] calldata newDeck, bytes calldata proof, uint256 newDeckDigest, uint256 gameId) public {
        _verify(newDeck, proof, newDeckDigest);

        // Save first 17 cards.
        for (uint256 i = 0; i < 68; i++) {
            deck[i] = newDeck[i];
        }

        // Save new card digest.
        deckDigest = newDeckDigest;

        // Write the remaining 35 cards down onto the event.
        for (uint256 i = 68; i < deckNum * 4; i++) {
            emit NewCardDeck(gameId, i, newDeck[i]);
        }
    }

    function _verify(uint256[] calldata newDeck, bytes calldata proof, uint256 newDeckDigest) public {
        uint256 deckLength = deckNum * 4;
        require(newDeck.length == deckLength, "SS01");

        uint256[] memory pi = new uint256[](deckLength + 70);
        for (uint256 i = 0; i < 68; i++) {
            pi[i] = deck[i];
        }
        pi[68] = deckDigest;
        for (uint256 i = 0; i < deckLength; i++) {
            pi[i + 69] = newDeck[i];
        }
        pi[deckLength + 69] = newDeckDigest;

        _verifyKey = VerifierKey_52.load;

        require(this.verifyShuffle(proof, pi, pkc), "SS00");
    }
}
