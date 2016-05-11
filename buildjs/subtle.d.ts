/// <reference path="promise.d.ts" />
import { CryptoKey } from "./key";
import * as iwc from "./iwebcrypto";
export declare class SubtleCrypto implements iwc.ISubtleCrypto {
    digest(algorithm: iwc.IAlgorithmIdentifier, data: iwc.TBuffer): Promise;
    generateKey(algorithm: iwc.AlgorithmType, extractable: boolean, keyUsages: string[]): Promise;
    sign(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): Promise;
    verify(algorithm: iwc.AlgorithmType, key: CryptoKey, signature: iwc.TBuffer, data: iwc.TBuffer): Promise;
    encrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): Promise;
    decrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: iwc.TBuffer): Promise;
    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: iwc.IAlgorithmIdentifier): Promise;
    unwrapKey(format: string, wrappedKey: iwc.TBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise;
    deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise;
    exportKey(format: string, key: CryptoKey): Promise;
    importKey(format: string, keyData: iwc.TBuffer, algorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise;
}
