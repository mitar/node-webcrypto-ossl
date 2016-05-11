"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var alg = require("./alg");
var key_1 = require("./key");
var native = require("./native");
var base64url = require("base64url");
exports.ALG_NAME_AES_CTR = "AES-CTR";
exports.ALG_NAME_AES_CBC = "AES-CBC";
exports.ALG_NAME_AES_CMAC = "AES-CMAC";
exports.ALG_NAME_AES_GCM = "AES-GCM";
exports.ALG_NAME_AES_CFB = "AES-CFB";
exports.ALG_NAME_AES_KW = "AES-KW";
var HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];
/**
 * Prepare array of data before it's using
 * @param data Array which must be prepared
 */
function prepare_data(data) {
    return (!Buffer.isBuffer(data)) ? ab2b(data) : data;
}
/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value wich must be converted to Buffer
 */
function ab2b(ab) {
    var buf = new Uint8Array(ab);
    return new Buffer(buf);
}
var Aes = (function (_super) {
    __extends(Aes, _super);
    function Aes() {
        _super.apply(this, arguments);
    }
    Aes.generateKey = function (alg, extractable, keyUsages, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenParams(alg);
            native.AesKey.generate(alg.length / 8, function (err, key) {
                if (!err) {
                    var aes = new key_1.CryptoKey(key, alg, "secret", extractable, keyUsages);
                    aes.usages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
                    cb(null, aes);
                }
                else {
                    cb(err, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    Aes.importKey = function (format, keyData, algorithm, extractable, keyUsages, cb) {
        try {
            this.checkAlgorithmIdentifier(algorithm);
            var raw = void 0;
            if (format === "jwk") {
                var jwk = keyData;
                // prepare data
                if (!jwk.k) {
                    throw new Error("Aes::ImportKey: Wrong JWK data");
                }
                raw = new Buffer(base64url.decode(jwk.k, "binary"), "binary");
            }
            else if (format === "raw") {
                raw = keyData;
            }
            else {
                throw new Error("Aes::ImportKeyWrong: Wrong iport key format");
            }
            var alg_1 = algorithm;
            alg_1.length = raw.length * 8;
            var aes = native.AesKey.import(raw, function (err, key) {
                if (!err) {
                    var aes_1 = new key_1.CryptoKey(key, alg_1, "secret", extractable, keyUsages);
                    aes_1.usages = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
                    cb(null, aes_1);
                }
                else
                    cb(err, null);
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    Aes.exportKey = function (format, key, cb) {
        try {
            var nkey = key.native;
            switch (format) {
                case "jwk":
                    var jwk_1 = {
                        kty: "oct",
                        alg: null,
                        key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                        k: null,
                        ext: true
                    };
                    // set alg
                    jwk_1.alg = "A" + key.algorithm.length + /-(\w+)$/.exec(key.algorithm.name)[1];
                    nkey.export(function (err, data) {
                        if (!err) {
                            jwk_1.k = base64url(data);
                            cb(null, jwk_1);
                        }
                        else {
                            cb(err, null);
                        }
                    });
                    break;
                case "raw":
                    nkey.export(cb);
                    break;
                default:
                    throw new Error("Aes::ExportKey: Wrong export key format");
            }
        }
        catch (e) {
            cb(e, null);
        }
    };
    Aes.checkKeyGenParams = function (alg) {
        if (!alg.length)
            throw new TypeError("AesKeyGenParams: length: Missing required property");
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new TypeError("AesKeyGenParams: length: Wrong value. Can be 128, 192, or 256");
        }
    };
    Aes.checkAlgorithmHashedParams = function (alg) {
        _super.checkAlgorithmHashedParams.call(this, alg);
        var _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
    };
    Aes.checkAlgorithmParams = function (alg) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new TypeError("AlgorithmParams: iv: Missing required property");
        if (alg.iv.length !== 16)
            throw new TypeError("AlgorithmParams: iv: Must be size of 16");
    };
    Aes.wc2ssl = function (alg) {
        throw new Error("Not realized");
    };
    return Aes;
}(alg.AlgorithmBase));
exports.Aes = Aes;
var AesGCM = (function (_super) {
    __extends(AesGCM, _super);
    function AesGCM() {
        _super.apply(this, arguments);
    }
    AesGCM.wc2ssl = function (alg) {
        var ret = "";
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new Error("Unknown AES key length in use '" + alg.length + "'");
        }
        return ret;
    };
    AesGCM.encrypt = function (algorithm, key, data, cb) {
        try {
            this.checkAlgorithmIdentifier(key.algorithm);
            this.checkKeyGenParams(key.algorithm);
            this.checkSecretKey(key);
            this.checkAlgorithmParams(algorithm);
            var nkey = key.native;
            var iv = algorithm.iv;
            if (!Buffer.isBuffer(iv))
                iv = new Buffer(algorithm.iv);
            nkey.encryptGcm(iv, data, algorithm.additionalData, algorithm.tagLength / 8, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    AesGCM.decrypt = function (algorithm, key, data, cb) {
        try {
            this.checkAlgorithmIdentifier(key.algorithm);
            this.checkKeyGenParams(key.algorithm);
            this.checkSecretKey(key);
            this.checkAlgorithmParams(algorithm);
            var nkey = key.native;
            var iv = algorithm.iv;
            if (!Buffer.isBuffer(iv))
                iv = new Buffer(algorithm.iv);
            nkey.decryptGcm(iv, data, algorithm.additionalData, algorithm.tagLength / 8, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    AesGCM.checkAlgorithmParams = function (alg) {
        if (!alg.tagLength)
            alg.tagLength = 128;
        switch (alg.tagLength) {
            case 128:
            case 120:
            case 112:
            case 104:
            case 96:
            case 64:
            case 32:
                break;
            default:
                throw new Error("AesGcm:AlgorithmParams: Wrong tag value. Can be 32, 64, 96, 104, 112, 120 or 128 (default)");
        }
        if (!alg.additionalData)
            alg.additionalData = new Buffer(0);
        if (!Buffer.isBuffer(alg.additionalData))
            alg.additionalData = new Buffer(alg.additionalData);
    };
    AesGCM.ALGORITHM_NAME = exports.ALG_NAME_AES_GCM;
    return AesGCM;
}(Aes));
exports.AesGCM = AesGCM;
var AesCBC = (function (_super) {
    __extends(AesCBC, _super);
    function AesCBC() {
        _super.apply(this, arguments);
    }
    AesCBC.wc2ssl = function (alg) {
        return alg.iv;
    };
    AesCBC.encrypt = function (alg, key, data, cb) {
        try {
            this.checkAlgorithmParams(alg);
            this.checkSecretKey(key);
            var iv = this.wc2ssl(alg);
            var nkey = key.native;
            var _alg = "CBC";
            nkey.encrypt(_alg, iv, data, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    AesCBC.decrypt = function (alg, key, data, cb) {
        try {
            this.checkAlgorithmParams(alg);
            this.checkSecretKey(key);
            var iv = this.wc2ssl(alg);
            var nkey = key.native;
            var _alg = "CBC";
            nkey.decrypt(_alg, iv, data, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    AesCBC.checkAlgorithmParams = function (alg) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new TypeError("AesCcm:AlgorithmParams: iv: Missing required property");
    };
    AesCBC.ALGORITHM_NAME = exports.ALG_NAME_AES_CBC;
    return AesCBC;
}(Aes));
exports.AesCBC = AesCBC;
//# sourceMappingURL=aes.js.map