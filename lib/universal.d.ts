/// <reference types="node" />
import nodeCrypto from "crypto";
export declare function universalWebcrypto(): Crypto | nodeCrypto.webcrypto.Crypto;
export declare function msgEncode(message: string): Uint8Array;
export declare function msgDecode(decrypted: BufferSource): string;
export declare function ab2str(buf: ArrayBuffer): string;
export declare function str2ab(str: string): ArrayBuffer;
export declare function arrayBufferToBase64(buf: ArrayBuffer): string;
export declare function base64ToArrayBuffer(data_base64: string): ArrayBuffer;
export declare function generateRandomKey(l?: number): string;
export declare class RSA {
    private static exportPublicKey;
    private static exportPrivateKey;
    private static importPublicKey;
    static importPrivateKey(pem: string): Promise<CryptoKey>;
    static publicEncrypt(msg: string, key: string): Promise<string>;
    static privateDecrypt(eMsg: string, key: string): Promise<string>;
    static generateKeyPair(): Promise<{
        privateKey: string;
        publicKey: string;
    }>;
    static getKeyPairClosure(): Promise<() => Promise<{
        privateKey: string;
        publicKey: string;
    }>>;
}
export declare class AES {
    static aesAlgorithm: string;
    private static base64ToCryptoKey;
    private static cryptoKeyToBase64;
    static generateKey(l?: number): Promise<string>;
    static encrypt(key: string, iv: string, msg: string): Promise<string>;
    static decrypt(key: string, iv: string, t: string): Promise<string>;
}
export declare function encryptWithAesRsaPb(data: string, publicKey: string): Promise<{
    encryptAesData: string;
    encryptAesKeyByRsa: string;
}>;
export declare function decryptWithAesRsaPv(encryptAesData: string, encryptAesKey: string, privateKey: string, timeoutSecond?: number): Promise<string>;
