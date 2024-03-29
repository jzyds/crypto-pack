import {
  RSA,
  decryptWithAesRsaPv,
  encryptWithAesRsaPb,
} from "../../src/node";

async function main() {
  const { privateKey, publicKey } = await RSA.generateKeyPair();

  const eMsg = await RSA.publicEncrypt("hello 你好 666 *@#¥", publicKey);
  const dMsg = await RSA.privateDecrypt(eMsg, privateKey);

  console.log("📢 [test.html:68]", eMsg, dMsg);

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
  console.log("📢 [t.ts:114]", JSON.parse(decryptData));
  console.log("decrypt duration -----", Date.now() - t2);
}

main();
