import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import * as key from "./key";
import { CryptoKey } from "./key";
import * as aes from "./aes";
export interface IJwkRsaPublicKey extends alg.IJwkKey {
    alg: string;
    e: Buffer;
    n: Buffer;
}
export interface IJwkRsaPrivateKey extends IJwkRsaPublicKey {
    d: Buffer;
    p: Buffer;
    q: Buffer;
    dp: Buffer;
    dq: Buffer;
    qi: Buffer;
}
export declare class Rsa extends alg.AlgorithmBase {
    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void;
    static importKey(format: string, keyData: Buffer | alg.IJwkKey, algorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static checkExponent(exp: Buffer): void;
    static checkRsaGenParams(alg: IRsaKeyGenParams): void;
    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier): void;
    static wc2ssl(alg: any): any;
}
export interface IRsaKeyGenParams extends iwc.IAlgorithmIdentifier {
    modulusLength: number;
    publicExponent: Uint8Array;
}
export interface IRsaOaepEncryptParams extends iwc.IAlgorithmIdentifier {
    label?: Uint8Array;
}
export declare class RsaPKCS1 extends Rsa {
    static ALGORITHM_NAME: string;
    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void;
    static exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static sign(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static verify(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
}
export declare class RsaPSS extends Rsa {
    static ALGORITHM_NAME: string;
}
export declare class RsaOAEP extends Rsa {
    static ALGORITHM_NAME: string;
    static generateKey(alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void;
    static exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static encrypt(alg: IRsaOaepEncryptParams, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static decrypt(alg: IRsaOaepEncryptParams, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static wrapKey(key: iwc.ICryptoKey, wrappingKey: iwc.ICryptoKey, algorithm: iwc.IAlgorithmIdentifier, cb: (err: Error, d: Buffer) => void): void;
    static wrapKey(key: key.CryptoKey, wrappingKey: CryptoKey, algorithm: IRsaOaepEncryptParams, cb: (err: Error, d: Buffer) => void): void;
    static unwrapKey(wrappedKey: Buffer, unwrappingKey: iwc.ICryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static unwrapKey(wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IRsaOaepEncryptParams, unwrappedAlgorithm: aes.IAesKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
}
