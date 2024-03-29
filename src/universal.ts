import nodeCrypto from "crypto";

// https://developer.mozilla.org/en-US/docs/Web/API/Crypto

function universalBtoa(str: string) {
  try {
    return btoa(str);
  } catch (err) {
    return Buffer.from(str).toString("base64");
  }
}

function universalAtob(b64Encoded: string) {
  try {
    return atob(b64Encoded);
  } catch (err) {
    return Buffer.from(b64Encoded, "base64").toString("binary");
  }
}

function getTimestampSeconds() {
  return Math.floor(Date.now() / 1000);
}

export function universalWebcrypto() {
  try {
    // browser
    return window.crypto;
  } catch (err) {
    // node
    return nodeCrypto.webcrypto;
  }
}

export function msgEncode(message: string) {
  let enc = new TextEncoder();
  return enc.encode(message);
}

export function msgDecode(decrypted: BufferSource) {
  let dec = new TextDecoder();
  return dec.decode(decrypted);
}

export function ab2str(buf: ArrayBuffer) {
  return String.fromCharCode.apply(null, [...new Uint8Array(buf)]);
}

export function str2ab(str: string) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export function arrayBufferToBase64(buf: ArrayBuffer) {
  return universalBtoa(ab2str(buf));
}

export function base64ToArrayBuffer(data_base64: string) {
  // base64 decode the string to get the binary data
  // convert from a binary string to an ArrayBuffer
  return str2ab(universalAtob(data_base64));
}

export function generateRandomKey(l = 16) {
  return arrayBufferToBase64(
    // @ts-ignore
    universalWebcrypto().getRandomValues(new Uint8Array(l))
  );
}

// ------ rsa
export class RSA {
  private static async exportPublicKey(key: CryptoKey) {
    const exported = await universalWebcrypto().subtle.exportKey("spki", key);

    return `-----BEGIN PUBLIC KEY-----\n${arrayBufferToBase64(
      exported
    )}\n-----END PUBLIC KEY-----`;
  }

  private static async exportPrivateKey(key: CryptoKey) {
    const exported = await universalWebcrypto().subtle.exportKey("pkcs8", key);

    return `-----BEGIN PRIVATE KEY-----\n${arrayBufferToBase64(
      exported
    )}\n-----END PRIVATE KEY-----`;
  }

  private static async importPublicKey(pem: string) {
    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem.substring(
      pemHeader.length,
      pem.length - pemFooter.length
    );
    return await universalWebcrypto().subtle.importKey(
      "spki",
      base64ToArrayBuffer(pemContents),
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"]
    );
  }

  public static async importPrivateKey(pem: string) {
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    const pemContents = pem.substring(
      pemHeader.length,
      pem.length - pemFooter.length
    );

    return await universalWebcrypto().subtle.importKey(
      "pkcs8",
      base64ToArrayBuffer(pemContents),
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"]
    );
  }

  public static async publicEncrypt(msg: string, key: string) {
    const encoded = msgEncode(msg);
    const importKey = await RSA.importPublicKey(key);
    const eBuffer = await universalWebcrypto().subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      importKey,
      encoded
    );
    return arrayBufferToBase64(eBuffer);
  }

  public static async privateDecrypt(eMsg: string, key: string) {
    let decrypted = await universalWebcrypto().subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      await RSA.importPrivateKey(key),
      base64ToArrayBuffer(eMsg)
    );
    return msgDecode(decrypted);
  }

  public static async generateKeyPair() {
    // https://crypto.stackexchange.com/questions/42097/what-is-the-maximum-size-of-the-plaintext-message-for-rsa-oaep
    // 1024 20 seconds
    // 2048 100 seconds
    const keyPair = await universalWebcrypto().subtle.generateKey(
      {
        name: "RSA-OAEP",
        // Consider using a 4096-bit key for systems that require long-term security
        // 1024 for less 62 string length
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );

    const pb_key_string = await RSA.exportPublicKey(keyPair.publicKey);
    const pv_key_string = await RSA.exportPrivateKey(keyPair.privateKey);

    return {
      privateKey: pv_key_string,
      publicKey: pb_key_string,
    };
  }

  public static async getKeyPairClosure() {
    let data: {
      privateKey: string;
      publicKey: string;
    } | null = null;
  
    return async function inner() {
      if (data === null) {
        data = await RSA.generateKeyPair();
      }
      return data;
    };
  }
}

// ------ aes
export class AES {
  static aesAlgorithm = "AES-CBC";

  private static async base64ToCryptoKey(key: string) {
    const exported = await universalWebcrypto().subtle.importKey(
      "raw",
      base64ToArrayBuffer(key),
      AES.aesAlgorithm,
      true,
      ["encrypt", "decrypt"]
    );
    return exported;
  }

  private static async cryptoKeyToBase64(key: CryptoKey) {
    const exported = await universalWebcrypto().subtle.exportKey("raw", key);
    return arrayBufferToBase64(exported);
  }

  public static async generateKey(l = 128) {
    // AES key data must be 128 or 256 bits
    return await AES.cryptoKeyToBase64(
      await universalWebcrypto().subtle.generateKey(
        {
          name: AES.aesAlgorithm,
          length: l,
        },
        true,
        ["encrypt", "decrypt"]
      )
    );
  }

  public static async encrypt(key: string, iv: string, msg: string) {
    const t = await universalWebcrypto().subtle.encrypt(
      {
        name: AES.aesAlgorithm,
        iv: base64ToArrayBuffer(iv),
      },
      await AES.base64ToCryptoKey(key),
      msgEncode(msg)
    );
    return arrayBufferToBase64(t);
  }

  public static async decrypt(key: string, iv: string, t: string) {
    let decrypted = await universalWebcrypto().subtle.decrypt(
      {
        name: AES.aesAlgorithm,
        iv: base64ToArrayBuffer(iv),
      },
      await AES.base64ToCryptoKey(key),
      base64ToArrayBuffer(t)
    );
    return msgDecode(decrypted);
  }
}

// ------ rsa + aes
export async function encryptWithAesRsaPb(data: string, publicKey: string) {
  const randomAesIv = generateRandomKey();
  const randomAesKey = await AES.generateKey();
  const encryptAesData = await AES.encrypt(randomAesKey, randomAesIv, data);
  const aesMsgString = JSON.stringify({
    k: randomAesKey,
    iv: randomAesIv,
    t: getTimestampSeconds(),
  });
  const encryptAesKeyByRsa = await RSA.publicEncrypt(
    aesMsgString,
    publicKey
    // padding,
    // oaepHash
  );
  return { encryptAesData, encryptAesKeyByRsa };
}

export async function decryptWithAesRsaPv(
  encryptAesData: string,
  encryptAesKey: string,
  privateKey: string,
  // 防重放
  timeoutSecond = -1
  // padding = defaultRsaPadding,
  // oaepHash = defaultRsaOaepHash
) {
  const decryptAesKeyIvString = await RSA.privateDecrypt(
    encryptAesKey,
    privateKey
    // padding,
    // oaepHash
  );
  const { k, iv, t } = JSON.parse(decryptAesKeyIvString);
  if (timeoutSecond > 0 && getTimestampSeconds() - t > timeoutSecond) {
    // 如果 timeoutSecond 参数设置大于 0，则配置生效
    // 如果解密时间戳 - 加密时间戳 > timeoutSecond
    // 报超时错误，解密失败
    throw Error("time out");
  }
  return await AES.decrypt(k, iv, encryptAesData);
}
