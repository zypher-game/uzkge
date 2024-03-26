// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.7.0 <0.9.0;

abstract contract Groth16Verifier {
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256 constant alphax = 9657238070900747270850134127207342063836775896456755772687970865046315915955;
    uint256 constant alphay = 2697735170765775544622437761582108993463590773433588253802052918158451426029;
    uint256 constant betax2 = 12429223697875723081527687538342171943491868349002819165890908454520351569605;
    uint256 constant betax1 = 14689678080692455997010794136306121434307951578200772024798807322394696902486;
    uint256 constant betay2 = 12803001360800917458942901523120304965894218664101869211251945885718205972434;
    uint256 constant betay1 = 15507276591611918832874712106658109966423735956962217292872289422132197239970;
    uint256 constant gammax2 = 19289510015421810870214361285696908718128932591411051856805464176345326542362;
    uint256 constant gammax1 = 17383364522414107015296521679361318151273235434663467052565951131876936081166;
    uint256 constant gammay2 = 13889289936016722517859396156609782805475693248823384508633879864395447280665;
    uint256 constant gammay1 = 14729444587320544659753422091817558843725892524053627940745419325144547338545;
    uint256 constant deltax2 = 2551475167714416766188258155878236367257553998193038054081988503339287183955;
    uint256 constant deltax1 = 16100414218509408371570773861288460187044489941521792630157390129651063222350;
    uint256 constant deltay2 = 1855877338944196725764206639899931099679326811272403111564003289821901500359;
    uint256 constant deltay1 = 18659479838118111224177246668974682558503482684885132990070622901313852820801;

    uint256 constant IC0x = 8231071344245304392905737599439338119805009493403479116079824564917948175155;
    uint256 constant IC0y = 123097163404658086984314950134846593956175025134110942267095710978257877661;

    uint256 constant IC1x = 11710780400242429612582559263679400553087647398117979924015767588598002746162;
    uint256 constant IC1y = 9386249052856628693084318817520959265345194606853124092904824287236913348442;

    uint256 constant IC2x = 16690210074887262851714468431276539269699621552598124046487633420991198886426;
    uint256 constant IC2y = 4673623169064950354522465171728358304039034026499101782089488108722303702285;

    uint256 constant IC3x = 5845393084964187117433471838403464075744586171896871224298485865162155827336;
    uint256 constant IC3y = 15275234627321610691155112036726604864050066413832963326581674349912072988792;

    uint256 constant IC4x = 48340697398687923083491449863732464095281556505897807354868991432210814245;
    uint256 constant IC4y = 10264889621790559421769697789322650145882004309084191414017184009688010508014;

    uint256 constant IC5x = 13253593231537008001563829790298352082807979231550827638774610107951630824627;
    uint256 constant IC5y = 18885661540081831825841595428502906951799338158700980302079062261386191614880;

    uint256 constant IC6x = 9803040101469704962298932749319797860811607510512239319797967436639389900637;
    uint256 constant IC6y = 16572130389315163624107961593078497076502659722535756008507313249749451057401;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;
    uint16 constant pLastMem = 896;

    // _proof = [A, B ,C]
    function verifyProof(uint256[8] calldata _proof, uint256[6] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(proof, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                // -A
                mstore(_pPairing, calldataload(proof))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(proof, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(add(proof, 64)))
                mstore(add(_pPairing, 96), calldataload(add(proof, 96)))
                mstore(add(_pPairing, 128), calldataload(add(proof, 128)))
                mstore(add(_pPairing, 160), calldataload(add(proof, 160)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(add(proof, 192)))
                mstore(add(_pPairing, 608), calldataload(add(proof, 224)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            // Validate all evaluations
            let isValid := checkPairing(_proof, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
