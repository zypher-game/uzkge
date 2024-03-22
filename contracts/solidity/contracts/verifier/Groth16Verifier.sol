// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.7.0 <0.9.0;

abstract contract Groth16Verifier {
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256 constant alphax = 16256165923103553519926347729425900872314204430994883104612610343111348135876;
    uint256 constant alphay = 19138652545956295660675617199594802505676299171380623649352005981478562443597;
    uint256 constant betax2 = 8204071324534901362341322439059587797414455100368336987686753165020369846845;
    uint256 constant betax1 = 6665433577658572066897486913299087481647452979210336608994345891701581856834;
    uint256 constant betay2 = 14834262973843077629865390891613017385609839712110447137888951068189007531011;
    uint256 constant betay1 = 16331941496885753419055646151848176696559025436200237673776742282742412967965;
    uint256 constant gammax2 = 19395211150219211391283530851566767038798848986875800621481809004353459821568;
    uint256 constant gammax1 = 20757124324097756225247531942005322123026046939826820803010761345582846713724;
    uint256 constant gammay2 = 9870927845400502661127907784295437871374570395824491513643064976625430961023;
    uint256 constant gammay1 = 7766404489786028606513551971777366421088003918093983243784536876175268136627;
    uint256 constant deltax2 = 2163309680161400121119682607794655964701512537494085645265412397027931826575;
    uint256 constant deltax1 = 3113283545088766024192829174616606999308594429959623964524929092618870403528;
    uint256 constant deltay2 = 1921476643110464450809770330667699614900900065953918273865752354000185267157;
    uint256 constant deltay1 = 5874921860466770388917190410934466283623612858778487631644429297361457438421;

    uint256 constant IC0x = 21032310447698900733489244462461327620034172087268937718486459736686330097542;
    uint256 constant IC0y = 15255358700585757092585473918754076738773749970617893456100369574687238860968;

    uint256 constant IC1x = 16715217290128382155589461578618236218430957776188273715735875193401306192313;
    uint256 constant IC1y = 15368024543709579921762320385741813490971153401525665424442005121364732127398;

    uint256 constant IC2x = 14274951064878040028256546927596989081768612233326778274916949637976011816760;
    uint256 constant IC2y = 6254462161320240732243528131880818559627315286143223997306859640249410473204;

    uint256 constant IC3x = 5364975381886818914093677874599753689915933780903550459994816244990917737679;
    uint256 constant IC3y = 4526703053836949638741254715952140627391613788977370991000243191073409095812;

    uint256 constant IC4x = 13817104078492523964688304194393832807277054048340506699203968948475441561857;
    uint256 constant IC4y = 13509663893899442455638082454515888969479420524783664872936091308415086582920;

    uint256 constant IC5x = 16914819523008621620287202063716635121588678411537131671993818040047759424213;
    uint256 constant IC5y = 12098080924417899419588547964089902275811924124479739512070960973355920054842;

    uint256 constant IC6x = 16968890734033980860207835394298675744606073588133402425478057457348548726313;
    uint256 constant IC6y = 8350946616796852576005794893850785435191413973586632109917286639736684400674;

    uint256 constant IC7x = 5588818621080811063986938798787918832692618028732440561053848238611142504983;
    uint256 constant IC7y = 226018260702723203566376453179106937624682067560259651059139245131362609172;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    // _proof = [A, B ,C]
    function verifyProof(uint256[8] calldata _proof, uint256[7] calldata _pubSignals) public view returns (bool) {
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

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

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

            checkField(calldataload(add(_pubSignals, 192)))

            // Validate all evaluations
            let isValid := checkPairing(_proof, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
