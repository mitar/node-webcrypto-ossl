/// <reference path="promise.d.ts" />
export interface IAlgorithmIdentifier {
    name: string;
    hash?: IAlgorithmIdentifier;
}
export declare type AlgorithmType = string | IAlgorithmIdentifier;
export interface IWebCrypto {
    subtle: ISubtleCrypto;
    getRandomValues(array: Buffer): Buffer;
}
export declare type TBuffer = ArrayBuffer | Buffer;
export interface ISubtleCrypto {
    digest(algorithm: IAlgorithmIdentifier, data: TBuffer): Promise;
    generateKey(algorithm: AlgorithmType, extractable: boolean, keyUsages: string[]): Promise;
    sign(algorithm: AlgorithmType, key: ICryptoKey, data: TBuffer): Promise;
    verify(algorithm: AlgorithmType, key: CryptoKey, signature: TBuffer, data: TBuffer): Promise;
    encrypt(algorithm: AlgorithmType, key: CryptoKey, data: TBuffer): Promise;
    decrypt(algorithm: AlgorithmType, key: CryptoKey, data: TBuffer): Promise;
    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: IAlgorithmIdentifier): Promise;
    unwrapKey(format: string, wrappedKey: TBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IAlgorithmIdentifier, unwrappedAlgorithm: IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise;
    exportKey(format: string, key: CryptoKey): Promise;
    importKey(format: string, keyData: TBuffer, algorithm: IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise;
}
export declare var KeyType: string[];
export declare var KeyUsage: string[];
export interface ICryptoKey {
    type: string;
    extractable: boolean;
    algorithm: any;
    usages: string[];
}
export interface ICryptoKeyPair {
    publicKey: ICryptoKey;
    privateKey: ICryptoKey;
}
