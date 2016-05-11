import * as iwc from "./iwebcrypto";
import * as native from "./native";
export declare class CryptoKey implements iwc.ICryptoKey {
    type: string;
    extractable: boolean;
    algorithm: iwc.IAlgorithmIdentifier;
    usages: string[];
    private native_;
    native: any;
    constructor(key: native.AesKey, alg: iwc.IAlgorithmIdentifier, type: string, extractable: boolean, keyUsages: string[]);
    constructor(key: native.Key, alg: iwc.IAlgorithmIdentifier, type: string, extractable: boolean, keyUsages: string[]);
}
