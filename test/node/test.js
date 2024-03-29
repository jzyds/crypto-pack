const {
  RSA,
  decryptWithAesRsaPv,
  encryptWithAesRsaPb,
  RSA_GenerateKeyPairToFile
} = require("../../lib/node");

async function main() {
  RSA_GenerateKeyPairToFile();
  const { privateKey, publicKey } = await RSA.generateKeyPair();

  const eMsg = await RSA.publicEncrypt("hello 你好 666 *@#¥", publicKey);
  const dMsg = await RSA.privateDecrypt(eMsg, privateKey);
  console.log("eMsg / dMsg", eMsg, dMsg);

  const t1 = Date.now();
  const { encryptAesData, encryptAesKeyByRsa } = await encryptWithAesRsaPb(
    JSON.stringify({
      asdasdas: "asdasdasasdasdasasdasdasasdasdasasdasdasasdasdasasdasdas",
      qw: "--------------------------------",
      han: "你好",
    }),
    publicKey
  );
  console.log("encrypt duration -----", Date.now() - t1);

  const t2 = Date.now();
  const decryptData = await decryptWithAesRsaPv(
    encryptAesData,
    encryptAesKeyByRsa,
    privateKey
  );
  console.log("decrypt duration -----", Date.now() - t2);
}

main();
