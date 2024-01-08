// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "./Utils.sol";

// A Twisted Edwards curve on scalar field of BN254. Also known as Baby-Jubjub.
// Modified from:
// https://github.com/yondonfu/sol-baby-jubjub/blob/master/contracts/CurveBabyJubJub.sol
// https://github.com/arkworks-rs/curves/tree/master/ed_on_bn254
//
// Curve information:
// * Base field: q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// * Scalar field: r = 2736030358979909402780800718157159386076813972158567259200215660948447373041
// * Valuation(q - 1, 2) = 28
// * Valuation(r - 1, 2) = 4
// * Curve equation: ax^2 + y^2 =1 + dx^2y^2, where
//    * a = 1
//    * d = 168696/168700 mod q
//        = 9706598848417545097372247223557719406784115219466060233080913168975159366771
library EdOnBN254 {
    uint256 internal constant Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant R = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    uint256 internal constant E_A = 1;
    uint256 internal constant E_D = 9706598848417545097372247223557719406784115219466060233080913168975159366771;

    struct Point {
        uint256 x;
        uint256 y;
    }

    function generator() internal pure returns (Point memory) {
        return
            Point(
                0x2B8CFD91B905CAE31D41E7DEDF4A927EE3BC429AAD7E344D59D2810D82876C32,
                0x2AAA6C24A758209E90ACED1F10277B762A7C1115DBC0E16AC276FC2C671A861F
            );
    }

    function zero() internal pure returns (Point memory) {
        return Point(0, 1);
    }

    function eq(Point memory a1, Point memory a2) internal pure returns (bool) {
        return a1.x == a2.x && a1.y == a2.y;
    }

    function add(Point memory a1, Point memory a2) internal view returns (Point memory) {
        if (a1.x == 0 && a1.y == 0) {
            return a2;
        }

        if (a2.x == 0 && a2.y == 0) {
            return a1;
        }

        uint256 x1x2 = mulmod(a1.x, a2.x, Q);
        uint256 y1y2 = mulmod(a1.y, a2.y, Q);
        uint256 dx1x2y1y2 = mulmod(E_D, mulmod(x1x2, y1y2, Q), Q);
        uint256 x3Num = addmod(mulmod(a1.x, a2.y, Q), mulmod(a1.y, a2.x, Q), Q);
        uint256 y3Num = submod(y1y2, mulmod(E_A, x1x2, Q), Q);

        return
            Point(
                mulmod(x3Num, inverse(addmod(1, dx1x2y1y2, Q)), Q),
                mulmod(y3Num, inverse(submod(1, dx1x2y1y2, Q)), Q)
            );
    }

    function double(Point memory a) internal view returns (Point memory) {
        return add(a, a);
    }

    function scalarMul(Point memory a, uint256 s) internal view returns (Point memory) {
        uint256 remaining = s;
        Point memory p = Point(a.x, a.y);
        Point memory ret = Point(0, 0);

        while (remaining != 0) {
            if ((remaining & 1) != 0) {
                ret = add(ret, p);
            }

            p = double(p);

            remaining = remaining / 2;
        }

        return ret;
    }

    function neg(Point memory a) internal pure returns (Point memory) {
        if (a.x == 0 && a.y == 0) return a;
        return Point(submod(0, a.x, Q), a.y);
    }

    function submod(uint256 _a, uint256 _b, uint256 _mod) internal pure returns (uint256) {
        return addmod(_a, _mod - _b, _mod);
    }

    function inverse(uint256 _a) internal view returns (uint256) {
        return expmod(_a, Q - 2, Q);
    }

    function expmod(uint256 _b, uint256 _e, uint256 _m) internal view returns (uint256 o) {
        assembly {
            let memPtr := mload(0x40)
            mstore(memPtr, 0x20)
            mstore(add(memPtr, 0x20), 0x20)
            mstore(add(memPtr, 0x40), 0x20)
            mstore(add(memPtr, 0x60), _b)
            mstore(add(memPtr, 0x80), _e)
            mstore(add(memPtr, 0xa0), _m)

            let success := staticcall(gas(), 0x05, memPtr, 0xc0, memPtr, 0x20)
            switch success
            case 0 {
                revert(0x0, 0x0)
            }
            default {
                o := mload(memPtr)
            }
        }
    }

    /// @dev Check if y-coordinate of G1 point is negative.
    function isYNegative(Point memory point) internal pure returns (bool) {
        return (point.y << 1) < Q;
    }

    function serialize(Point memory point) internal pure returns (bytes memory res) {
        uint256 mask = 0;
        // Edward curve does not have an infinity flag.
        // Set the 255-th bit to 1 for positive Y
        // See: https://github.com/arkworks-rs/algebra/blob/d6365c3a0724e5d71322fe19cbdb30f979b064c8/serialize/src/flags.rs#L148
        if (!isYNegative(point)) {
            mask = 0x8000000000000000000000000000000000000000000000000000000000000000;
        }

        return abi.encodePacked(Utils.reverseEndianness(point.x | mask));
    }
}
