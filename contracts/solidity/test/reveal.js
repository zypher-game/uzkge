const { expect } = require("chai");

describe("Reveal Verify Contract", function () {
  it("reveal verify must success", async function () {
    const [owner] = await ethers.getSigners();
    const revealVerifier = await ethers.deployContract("RevealVerifier");

    const res1 = await revealVerifier.verifyReveal(
      { x: "0x141b2d002bbc5b15ceb13eab84140979048d07360cebe4d7e161bc3e07b0e2d5", y: "0x2e906cedbeb30bb194358e38084c9e7900bf8d64febafc7e76b2138ff6116560"},
      { e1: { x: "0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32", y: "0x2aaa6c24a758209e90aced1f10277b762a7c1115dbc0e16ac276fc2c671a861f"}, e2: { x: "0x1db7221bed666a9654350a06674426f7db78d936922805e4677d8dab65d63118", y: "0x1bb682502b25eb7cec6a8744cb3391b28e593b29afd18c54bde24709edd4a280" }},
      { x: "0x141b2d002bbc5b15ceb13eab84140979048d07360cebe4d7e161bc3e07b0e2d5", y: "0x2e906cedbeb30bb194358e38084c9e7900bf8d64febafc7e76b2138ff6116560"},
      "0x169be63c3d815c43b43bbb7c30914a2af57ab107c899d4aa29a71cdc57d6add42a6150c959d82a63993b0c2480bab343fcd8eb282de2be770cf0cc36fda42d44169be63c3d815c43b43bbb7c30914a2af57ab107c899d4aa29a71cdc57d6add42a6150c959d82a63993b0c2480bab343fcd8eb282de2be770cf0cc36fda42d4405d1e3ea4fc09b67e6889856ff400bdd96ed7028c723e9458d49f56d0063f9f2"
    );
    // const { gasUsed } = await res1.wait(); // remove view from function
    // console.log("gas used: ", gasUsed);
    expect(res1).to.equal(true);
  });

  it("unmask verify must success", async function () {
    const [owner] = await ethers.getSigners();
    const revealVerifier = await ethers.deployContract("RevealVerifier");

    const res2 = await revealVerifier.unmask(
      { e1: { x: "0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32", y: "0x2aaa6c24a758209e90aced1f10277b762a7c1115dbc0e16ac276fc2c671a861f"}, e2: { x: "0x24020dff6d7a267256b299f2177041b43447ead73bc5c4594098e60ae1f56f55", y: "0x1e702d31afd034197dd9590479081edc285a5f26b1427f3924cb5306985faf69" }},
      [{ x: "0x132cdc533cb7a808ef809ea508c94336856388ad5b56827ff1f6d2d0a890be00", y: "0x201cddbcaa245f710bfc214f75a85ce4f0b4c6b27226ada41e5a6d031b94e283"}, { x: "0x12bff50dc3655855579f4c39c3f2879a886723b2403dd42f3776e528116dd22b", y: "0x0c2dd92778bf7d25e1323177e65e7a6c35088bcb8269dc8a1ddfc71d5fb3483b"}, { x: "0x1b3ab4009608e247a33ae549a40ee9340b0aa2e15a2a4beeef2cd7018ad22ae4", y: "0x0d4c11b5cd5b74d64ba2b0eb0b4e14a2ed75463d0948cef720fca9e32c15c57b"}, { x: "0x0d63963c79942ec501c1bb3ac733da088c5461b2b993286d9ca463cc1f8c56cd", y: "0x2f4fcc689f324f9f09689e0ccdba6ec24bdff433f1cbb175aadb069522926b01"},],
    );
    // const { gasUsed } = await res2.wait(); // remove view from function
    // console.log("gas used: ", gasUsed);
    expect(res2.y).to.equal("0x0e7e20b3cb30785b64cd6972e2ddf919db64d03d6cf01456243c5ef2fb766a65");
  });
});
