import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import { CryptoKey } from "./key";
export declare var ALG_NAME_AES_CTR: string;
export declare var ALG_NAME_AES_CBC: string;
export declare var ALG_NAME_AES_CMAC: string;
export declare var ALG_NAME_AES_GCM: string;
export declare var ALG_NAME_AES_CFB: string;
export declare var ALG_NAME_AES_KW: string;
export interface IJwkAesKey extends alg.IJwkKey {
    alg: string;
    k: Buffer;
}
export declare class Aes extends alg.AlgorithmBase {
    static generateKey(alg: IAesKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static importKey(format: string, keyData: Buffer | alg.IJwkKey, algorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static checkKeyGenParams(alg: iwc.IAlgorithmIdentifier): any;
    static checkKeyGenParams(alg: IAesKeyGenParams): any;
    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier): void;
    static checkAlgorithmParams(alg: IAesAlgorithmParams): void;
    static wc2ssl(alg: IAesAlgorithmParams): void;
}
export interface IAesKeyGenParams extends iwc.IAlgorithmIdentifier {
    length: number;
}
export interface IAesAlgorithmParams extends iwc.IAlgorithmIdentifier {
    iv: Buffer;
}
export interface IAesCBCAlgorithmParams extends IAesAlgorithmParams {
}
export interface IAesGCMAlgorithmParams extends IAesCBCAlgorithmParams {
    additionalData: Buffer;
    tagLength: number;
}
export declare class AesGCM extends Aes {
    static ALGORITHM_NAME: string;
    static wc2ssl(alg: any): string;
    static encrypt(algorithm: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static encrypt(algorithm: IAesGCMAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static decrypt(algorithm: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static decrypt(algorithm: IAesGCMAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static checkAlgorithmParams(alg: IAesGCMAlgorithmParams): void;
}
export declare class AesCBC extends Aes {
    static ALGORITHM_NAME: string;
    static wc2ssl(alg: IAesAlgorithmParams): Buffer;
    static encrypt(alg: IAesCBCAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static decrypt(alg: IAesCBCAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static checkAlgorithmParams(alg: IAesCBCAlgorithmParams): void;
}
