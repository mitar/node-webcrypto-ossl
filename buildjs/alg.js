"use strict";
var base64url = require("base64url");
var AlgorithmBase = (function () {
    function AlgorithmBase() {
    }
    AlgorithmBase.generateKey = function (alg, extractable, keyUsages, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.sign = function (alg, key, data, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.verify = function (alg, key, signature, data, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.encrypt = function (alg, key, data, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.decrypt = function (alg, key, data, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.wrapKey = function (key, wrappingKey, alg, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.unwrapKey = function (wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedAlgorithm, extractable, keyUsages, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.exportKey = function (format, key, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    AlgorithmBase.importKey = function (format, keyData, algorithm, extractable, keyUsages, cb) {
        try {
            throw new Error("Method is not supported");
        }
        catch (e) {
            cb(e, null);
        }
    };
    /**
     * check type of exported data
     * @param {string} type type of exported data (raw, jwk, spki, pkcs8)
     */
    AlgorithmBase.checkKeyType = function (type) {
        var ERROR_TYPE = "KeyType";
        var _type = type.toLowerCase();
        switch (type) {
            case "spki":
            case "pkcs8":
            case "jwk":
            case "raw":
                break;
            default:
                throw new TypeError(ERROR_TYPE + ": Unknown key type in use '" + _type + "'");
        }
    };
    AlgorithmBase.checkExportKey = function (format, key) {
        var ERROR_TYPE = "ExportKey";
        var _format = format.toLowerCase();
        this.checkKeyType(format);
        if (key.type === "private") {
            if (_format !== "pkcs8")
                throw new TypeError(ERROR_TYPE + ": Only 'pkcs8' is allowed");
        }
        else if (key.type === "public") {
            if (_format !== "spki")
                throw new TypeError(ERROR_TYPE + ": Only 'spki' is allowed");
        }
        else {
            throw new TypeError(ERROR_TYPE + ": Only for 'private' and 'public' key allowed");
        }
    };
    AlgorithmBase.checkAlgorithmIdentifier = function (alg) {
        if (typeof alg !== "object")
            throw TypeError("AlgorithmIdentifier: Algorithm must be an Object");
        if (!(alg.name && typeof (alg.name) === "string"))
            throw TypeError("AlgorithmIdentifier: Missing required property name");
        if (alg.name.toLowerCase() !== this.ALGORITHM_NAME.toLowerCase())
            throw new Error("AlgorithmIdentifier: Wrong algorithm name. Must be " + this.ALGORITHM_NAME);
        alg.name = this.ALGORITHM_NAME;
    };
    AlgorithmBase.checkAlgorithmHashedParams = function (alg) {
        if (!alg.hash)
            throw new TypeError("AlgorithmHashedParams: Missing required property hash");
        if (typeof alg.hash !== "object")
            throw TypeError("AlgorithmIdentifier: Algorithm must be an Object");
        if (!(alg.hash.name && typeof (alg.hash.name) === "string"))
            throw TypeError("AlgorithmIdentifier: Missing required property name");
    };
    AlgorithmBase.checkKey = function (key, type) {
        if (!key)
            throw new TypeError("CryptoKey: Key can not be null");
        if (key.type !== type)
            throw new TypeError("CryptoKey: Wrong key type in use. Must be '" + type + "'");
    };
    AlgorithmBase.checkPrivateKey = function (key) {
        this.checkKey(key, "private");
    };
    AlgorithmBase.checkPublicKey = function (key) {
        this.checkKey(key, "public");
    };
    AlgorithmBase.checkSecretKey = function (key) {
        this.checkKey(key, "secret");
    };
    AlgorithmBase.ALGORITHM_NAME = "";
    return AlgorithmBase;
}());
exports.AlgorithmBase = AlgorithmBase;
//# sourceMappingURL=alg.js.map