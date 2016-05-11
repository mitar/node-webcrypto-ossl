import * as iwc from "./iwebcrypto";
import * as key from "./key";
export interface IJwkKey {
    kty: string;
    ext?: boolean;
    key_ops: string[];
}
export interface IAlgorithmBase {
    generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void;
    sign(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    verify(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
    encrypt(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    decrypt(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    wrapKey(key: key.CryptoKey, wrappingKey: key.CryptoKey, alg: iwc.IAlgorithmIdentifier, cb: (err: Error, d: Buffer) => void): void;
    unwrapKey(wrappedKey: Buffer, unwrappingKey: key.CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    importKey(format: string, keyData: Buffer | IJwkKey, algorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
}
export declare class AlgorithmBase {
    static ALGORITHM_NAME: string;
    static generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey | iwc.ICryptoKeyPair) => void): void;
    static sign(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static verify(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
    static encrypt(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static decrypt(alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static wrapKey(key: key.CryptoKey, wrappingKey: key.CryptoKey, alg: iwc.IAlgorithmIdentifier, cb: (err: Error, d: Buffer) => void): void;
    static unwrapKey(wrappedKey: Buffer, unwrappingKey: key.CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static exportKey(format: string, key: key.CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static importKey(format: string, keyData: Buffer | IJwkKey, algorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    /**
     * check type of exported data
     * @param {string} type type of exported data (raw, jwk, spki, pkcs8)
     */
    static checkKeyType(type: string): void;
    static checkExportKey(format: string, key: CryptoKey): void;
    static checkAlgorithmIdentifier(alg: any): void;
    static checkAlgorithmHashedParams(alg: any): void;
    static checkKey(key: iwc.ICryptoKey, type: string): void;
    static checkPrivateKey(key: iwc.ICryptoKey): void;
    static checkPublicKey(key: iwc.ICryptoKey): void;
    static checkSecretKey(key: iwc.ICryptoKey): void;
}
