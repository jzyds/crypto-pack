import { RSA } from "./universal";
import fs from "fs";

export async function RSA_GenerateKeyPairToFile() {
  const { privateKey, publicKey } = await RSA.generateKeyPair();
  fs.writeFileSync("./.store/publicKey.pem", publicKey);
  fs.writeFileSync("./.store/privateKey.pem", privateKey);
}

export * from "./universal";
