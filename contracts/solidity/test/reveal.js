const { expect } = require("chai");

describe("Reveal Verify Contract", function () {
  it("aggregate keys must success", async function () {
    const [owner] = await ethers.getSigners();
    const revealVerifier = await ethers.deployContract("RevealVerifier");

    const res1 = await revealVerifier.aggregateKeys([
      { x: "0x1c1018979d2b1b19481da75668b69b5db43766689457507bf4e0951832edf114", y: "0x037186a98dcfe1b6a29fe4cb25dc38945b680b9350bf11c9c5be078dfa087995" },
      { x: "0x00f713c48e8cda27d5dabb68fe5e92a9ad59dbc276b5a407a099192b52514e34", y: "0x286fef04eab062fa4054bfa784c3f416f11e3df91fca4eb75315dd099f2b5471" },
      { x: "0x170b3f6073aa25291ec30fff6f09c1195045de8a1740fd2c86951520b147ceaf", y: "0x0c8f9f1a44634062ef6cec79a3c9129bcb8316babd709cc5ebdf17ad18de6135" },
      { x: "0x069a99c86ae73b02d7ee4b4f8ece22cca57e668147efbb967e99ab00ca457404", y: "0x2a8a9d2db35110dbe4612c1c3923f8be057dbceeca9623feb5364b41c48a9855" }
    ]);
    // const { gasUsed } = await res1.wait(); // remove view from function
    // console.log("gas used: ", gasUsed); // 42263
    expect(ethers.toBeHex(res1[0])).to.equal("0x1752b4b41ccda158d6ff427c6be1c05aa1a94231fc22fdc59cd64c2a3c213152");
    expect(ethers.toBeHex(res1[1])).to.equal("0x141404cf07d59feae8b3f344d7431dc4e1cbb0792e5dfe4710eb107af5ef8815");
  });

  it("reveal verify must success", async function () {
    const [owner] = await ethers.getSigners();
    const revealVerifier = await ethers.deployContract("RevealVerifier");

    const res1 = await revealVerifier.verifyReveal(
      { x: "0x141b2d002bbc5b15ceb13eab84140979048d07360cebe4d7e161bc3e07b0e2d5", y: "0x2e906cedbeb30bb194358e38084c9e7900bf8d64febafc7e76b2138ff6116560" },
      [
        "0x1db7221bed666a9654350a06674426f7db78d936922805e4677d8dab65d63118",
        "0x1bb682502b25eb7cec6a8744cb3391b28e593b29afd18c54bde24709edd4a280",
        "0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32",
        "0x2aaa6c24a758209e90aced1f10277b762a7c1115dbc0e16ac276fc2c671a861f"
      ],
      { x: "0x141b2d002bbc5b15ceb13eab84140979048d07360cebe4d7e161bc3e07b0e2d5", y: "0x2e906cedbeb30bb194358e38084c9e7900bf8d64febafc7e76b2138ff6116560" },
      "0x169be63c3d815c43b43bbb7c30914a2af57ab107c899d4aa29a71cdc57d6add42a6150c959d82a63993b0c2480bab343fcd8eb282de2be770cf0cc36fda42d44169be63c3d815c43b43bbb7c30914a2af57ab107c899d4aa29a71cdc57d6add42a6150c959d82a63993b0c2480bab343fcd8eb282de2be770cf0cc36fda42d4405d1e3ea4fc09b67e6889856ff400bdd96ed7028c723e9458d49f56d0063f9f2"
    );
    // const { gasUsed } = await res1.wait(); // remove view from function
    // console.log("gas used: ", gasUsed); // 7629888
    expect(res1).to.equal(true);
  });

  it("unmask verify must success", async function () {
    const [owner] = await ethers.getSigners();
    const revealVerifier = await ethers.deployContract("RevealVerifier");

    const res2 = await revealVerifier.unmask(
      [
        "0x24020dff6d7a267256b299f2177041b43447ead73bc5c4594098e60ae1f56f55",
        "0x1e702d31afd034197dd9590479081edc285a5f26b1427f3924cb5306985faf69",
        "0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32",
        "0x2aaa6c24a758209e90aced1f10277b762a7c1115dbc0e16ac276fc2c671a861f"
      ],
      [
        { x: "0x132cdc533cb7a808ef809ea508c94336856388ad5b56827ff1f6d2d0a890be00", y: "0x201cddbcaa245f710bfc214f75a85ce4f0b4c6b27226ada41e5a6d031b94e283" },
        { x: "0x12bff50dc3655855579f4c39c3f2879a886723b2403dd42f3776e528116dd22b", y: "0x0c2dd92778bf7d25e1323177e65e7a6c35088bcb8269dc8a1ddfc71d5fb3483b" },
        { x: "0x1b3ab4009608e247a33ae549a40ee9340b0aa2e15a2a4beeef2cd7018ad22ae4", y: "0x0d4c11b5cd5b74d64ba2b0eb0b4e14a2ed75463d0948cef720fca9e32c15c57b" },
        { x: "0x0d63963c79942ec501c1bb3ac733da088c5461b2b993286d9ca463cc1f8c56cd", y: "0x2f4fcc689f324f9f09689e0ccdba6ec24bdff433f1cbb175aadb069522926b01" },
      ],
    );
    // const { gasUsed } = await res2.wait(); // remove view from function
    // console.log("gas used: ", gasUsed); // 49827
    expect(res2.y).to.equal("0x0e7e20b3cb30785b64cd6972e2ddf919db64d03d6cf01456243c5ef2fb766a65");
  });

  it("reveal with snark verify must success", async function () {
    const [owner] = await ethers.getSigners();
    const revealVerifier = await ethers.deployContract("RevealVerifier");

    const res1 = await revealVerifier.verifyRevealWithSnark(
      [
        "7352128854079814232961172193688511100938467652834774341537018640509968470264",  // mask_card.e1.x
        "19728474252532032163676702131895351364313098934427086156813602243041979731593", // mask_card.e1.y
        "11002517068372888488854523110977229544610170502106015927522862914672870189927", // reveal_card.x
        "352307422658699541260347306774021217934610119053983343748464517473253849018",   // reveal_card.y
        "14634768033461582854187110012464718445878357827387488660889291173743117352958", // pk.x
        "15757834434594317522288384436361162410631041685092078340158295657808102912925", // pk.y
      ],
      [
        "14639757723053936486091077794403356648612994510556307300554171777836459203233",
        "20246694126396708203018563740548027855661926132529276548076997335881936431640",
        "10189714267019054455593145215486106914190700664520025397274475374810444583042",
        "15987352974948392387464925138184518889689966740159023253699103772650423265668",
        "15726331014087280384906698905024511720594759651414238836663385518306430258200",
        "21765528274142624345247281108602526569830026135730664972143333610635109097663",
        "2107724035290304330330116408458621474645501458189143582994855880604814354112",
        "14228663451491988475253052287937411541099835022264464353829475748009167709212"
      ]
    );
    // const { gasUsed } = await res1.wait(); // remove view from function
    // console.log("gas used: ", gasUsed); // 250296
    expect(res1).to.equal(true);
  });
});
