import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import * as key from "./key";
import { CryptoKey } from "./key";
export interface IJwkEcPublicKey extends alg.IJwkKey {
    x: Buffer;
    y: Buffer;
    crv: string;
}
export interface IJwkEcPrivateKey extends IJwkEcPublicKey {
    d: Buffer;
}
export declare class Ec extends alg.AlgorithmBase {
    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static importKey(format: string, keyData: Buffer | alg.IJwkKey, algorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static importKey(format: string, keyData: Buffer | alg.IJwkKey, algorithm: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: CryptoKey) => void): void;
    static exportKey(format: string, key: iwc.ICryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static checkKeyGenParams(alg: IEcKeyGenParams): void;
    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier): void;
    static checkAlgorithmParams(alg: IEcAlgorithmParams): void;
    static wc2ssl(alg: IEcAlgorithmParams): void;
}
export interface IEcKeyGenParams extends iwc.IAlgorithmIdentifier {
    namedCurve: string;
}
export interface IEcAlgorithmParams extends iwc.IAlgorithmIdentifier {
    namedCurve: string;
    public?: CryptoKey;
}
export interface IEcdsaAlgorithmParams extends IEcAlgorithmParams {
    hash: {
        name: string;
    };
}
export declare class Ecdsa extends Ec {
    static ALGORITHM_NAME: string;
    static wc2ssl(alg: any): any;
    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static sign(alg: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static sign(alg: IEcdsaAlgorithmParams, key: CryptoKey, data: Buffer, cb: (err: Error, d: Buffer) => void): void;
    static verify(alg: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
    static verify(alg: IEcdsaAlgorithmParams, key: CryptoKey, signature: Buffer, data: Buffer, cb: (err: Error, d: boolean) => void): void;
    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
}
export interface IEcDhAlgorithmParams extends IEcAlgorithmParams {
}
export declare class Ecdh extends Ec {
    static ALGORITHM_NAME: string;
    static generateKey(alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static generateKey(alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKeyPair) => void): void;
    static deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static deriveKey(algorithm: IEcDhAlgorithmParams, baseKey: key.CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], cb: (err: Error, d: iwc.ICryptoKey) => void): void;
    static exportKey(format: string, key: CryptoKey, cb: (err: Error, d: Object | Buffer) => void): void;
    static checkAlgorithmParams(alg: IEcDhAlgorithmParams): void;
}
