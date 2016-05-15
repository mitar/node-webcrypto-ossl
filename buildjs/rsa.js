"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var alg = require("./alg");
var key = require("./key");
var key_1 = require("./key");
var native = require("./native");
var aes = require("./aes");
var base64url = require("base64url");
var ALG_NAME_RSA_PKCS1 = "RSASSA-PKCS1-v1_5";
var ALG_NAME_RSA_PSS = "RSA-PSS";
var ALG_NAME_RSA_OAEP = "RSA-OAEP";
var HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];
var Rsa = (function (_super) {
    __extends(Rsa, _super);
    function Rsa() {
        _super.apply(this, arguments);
    }
    Rsa.generateKey = function (alg, extractable, keyUsages, cb) {
        try {
            var size = alg.modulusLength;
            var exp = new Buffer(alg.publicExponent);
            this.checkExponent(exp);
            // convert exp
            var nExp = 0;
            if (exp.toString("hex") === "010001")
                nExp = 1;
            native.Key.generateRsa(size, nExp, function (err, key) {
                try {
                    if (err) {
                        throw new Error("Rsa: Can not generate new key\n" + err.message);
                    }
                    else {
                        cb(null, {
                            privateKey: new key_1.CryptoKey(key, alg, "private", extractable, keyUsages),
                            publicKey: new key_1.CryptoKey(key, alg, "public", extractable, keyUsages)
                        });
                    }
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    Rsa.importKey = function (format, keyData, algorithm, extractable, keyUsages, cb) {
        try {
            var _format = format.toLocaleLowerCase();
            switch (_format) {
                case "jwk":
                    var jwk_1 = keyData;
                    this.checkAlgorithmIdentifier(algorithm);
                    this.checkAlgorithmHashedParams(algorithm);
                    // prepare data
                    jwk_1.n = new Buffer(base64url.decode(jwk_1.n, "binary"), "binary");
                    jwk_1.e = new Buffer(base64url.decode(jwk_1.e, "binary"), "binary");
                    var key_type_1 = native.KeyType.PUBLIC;
                    if (jwk_1.d) {
                        key_type_1 = native.KeyType.PRIVATE;
                        jwk_1.d = new Buffer(base64url.decode(jwk_1.d, "binary"), "binary");
                        jwk_1.p = new Buffer(base64url.decode(jwk_1.p, "binary"), "binary");
                        jwk_1.q = new Buffer(base64url.decode(jwk_1.q, "binary"), "binary");
                        jwk_1.dp = new Buffer(base64url.decode(jwk_1.dp, "binary"), "binary");
                        jwk_1.dq = new Buffer(base64url.decode(jwk_1.dq, "binary"), "binary");
                        jwk_1.qi = new Buffer(base64url.decode(jwk_1.qi, "binary"), "binary");
                    }
                    native.Key.importJwk(jwk_1, key_type_1, function (err, key) {
                        try {
                            if (err)
                                throw new Error("ImportKey: Can not import key from JWK\n" + err.message);
                            var rsa = new key_1.CryptoKey(key, algorithm, key_type_1 ? "private" : "public", extractable, keyUsages);
                            rsa.algorithm.modulusLength = jwk_1.n.length * 8;
                            rsa.algorithm.publicExponent = new Uint8Array(jwk_1.e);
                            cb(null, rsa);
                        }
                        catch (e) {
                            cb(e, null);
                        }
                    });
                    break;
                case "pkcs8":
                case "spki":
                    if (!Buffer.isBuffer(keyData))
                        throw new Error("ImportKey: keyData is not a Buffer");
                    var importFunction = native.Key.importPkcs8;
                    if (_format === "spki")
                        importFunction = native.Key.importSpki;
                    importFunction(keyData, function (err, key) {
                        try {
                            if (err)
                                throw new Error("ImportKey: Can not import key for " + format + "\n" + err.message);
                            var rsa = new key_1.CryptoKey(key, algorithm, format.toLocaleLowerCase() === "spki" ? "public" : "private", extractable, keyUsages);
                            rsa.algorithm.modulusLength = key.modulusLength() * 8;
                            rsa.algorithm.publicExponent = new Uint8Array(key.publicExponent());
                            cb(null, rsa);
                        }
                        catch (e) {
                            cb(err, null);
                        }
                    });
                    break;
                default:
                    throw new Error("ImportKey: Wrong format value '" + format + "'");
            }
        }
        catch (e) {
            cb(e, null);
        }
    };
    Rsa.exportKey = function (format, key, cb) {
        try {
            var nkey = key.native;
            var type = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
            switch (format.toLocaleLowerCase()) {
                case "jwk":
                    nkey.exportJwk(type, function (err, data) {
                        try {
                            var jwk = data;
                            // convert base64 -> base64url for all props
                            jwk.e = base64url(jwk.e);
                            jwk.n = base64url(jwk.n);
                            if (key.type === "private") {
                                jwk.d = base64url(jwk.d);
                                jwk.p = base64url(jwk.p);
                                jwk.q = base64url(jwk.q);
                                jwk.dp = base64url(jwk.dp);
                                jwk.dq = base64url(jwk.dq);
                                jwk.qi = base64url(jwk.qi);
                            }
                            cb(null, jwk);
                        }
                        catch (e) {
                            cb(e, null);
                        }
                    });
                    break;
                case "spki":
                    this.checkPublicKey(key);
                    nkey.exportSpki(cb);
                    break;
                case "pkcs8":
                    this.checkPrivateKey(key);
                    nkey.exportPkcs8(cb);
                    break;
                default:
                    throw new Error("ExportKey: Unknown export frmat '" + format + "'");
            }
        }
        catch (e) {
            cb(e, null);
        }
    };
    Rsa.checkExponent = function (exp) {
        var e = exp.toString("hex");
        if (!(e === "03" || e === "010001"))
            throw new TypeError("RsaKeyGenParams: Wrong publicExponent value");
    };
    Rsa.checkRsaGenParams = function (alg) {
        if (!alg.modulusLength)
            throw new TypeError("RsaKeyGenParams: modulusLength: Missing required property");
        if (alg.modulusLength < 256 || alg.modulusLength > 16384)
            throw new TypeError("RsaKeyGenParams: The modulus length must be a multiple of 8 bits and >= 256 and <= 16384");
        if (!(alg.publicExponent && alg.publicExponent instanceof Uint8Array))
            throw new TypeError("RsaKeyGenParams: publicExponent: Missing or not a Uint8Array");
    };
    Rsa.checkAlgorithmHashedParams = function (alg) {
        _super.checkAlgorithmHashedParams.call(this, alg);
        var _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
    };
    Rsa.wc2ssl = function (alg) {
        RsaPKCS1.checkAlgorithmHashedParams(alg);
        var _alg = alg.hash.name.toUpperCase().replace("-", "");
        return _alg;
    };
    return Rsa;
}(alg.AlgorithmBase));
exports.Rsa = Rsa;
var RsaPKCS1 = (function (_super) {
    __extends(RsaPKCS1, _super);
    function RsaPKCS1() {
        _super.apply(this, arguments);
    }
    RsaPKCS1.generateKey = function (alg, extractable, keyUsages, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkRsaGenParams(alg);
            this.checkAlgorithmHashedParams(alg);
            _super.generateKey.call(this, alg, extractable, keyUsages, function (err, key) {
                try {
                    if (err) {
                        cb(err, null);
                    }
                    else {
                        if (key.type === "public") {
                            key.usages = ["verify"];
                        }
                        else {
                            key.usages = ["sign"];
                        }
                        cb(null, key);
                    }
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaPKCS1.exportKey = function (format, key, cb) {
        try {
            _super.exportKey.call(this, format, key, function (err, data) {
                if (err)
                    return cb(err, null);
                try {
                    if (format === "jwk") {
                        var jwk = data;
                        // set alg
                        var reg = /(\d+)$/;
                        jwk.alg = "RS" + reg.exec(key.algorithm.hash.name)[1];
                        jwk.ext = true;
                        if (key.type === "public") {
                            jwk.key_ops = ["verify"];
                        }
                        else {
                            jwk.key_ops = ["sign"];
                        }
                        cb(null, jwk);
                    }
                    else
                        cb(null, data);
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaPKCS1.sign = function (alg, key, data, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPrivateKey(key);
            var _alg = this.wc2ssl(key.algorithm);
            var nkey = key.native;
            nkey.sign(_alg, data, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaPKCS1.verify = function (alg, key, signature, data, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPublicKey(key);
            var _alg = this.wc2ssl(key.algorithm);
            var nkey = key.native;
            nkey.verify(_alg, data, signature, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaPKCS1.ALGORITHM_NAME = ALG_NAME_RSA_PKCS1;
    return RsaPKCS1;
}(Rsa));
exports.RsaPKCS1 = RsaPKCS1;
var RsaPSS = (function (_super) {
    __extends(RsaPSS, _super);
    function RsaPSS() {
        _super.apply(this, arguments);
    }
    RsaPSS.ALGORITHM_NAME = ALG_NAME_RSA_PSS;
    return RsaPSS;
}(Rsa));
exports.RsaPSS = RsaPSS;
var RsaOAEP = (function (_super) {
    __extends(RsaOAEP, _super);
    function RsaOAEP() {
        _super.apply(this, arguments);
    }
    RsaOAEP.generateKey = function (alg, extractable, keyUsages, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkRsaGenParams(alg);
            this.checkAlgorithmHashedParams(alg);
            _super.generateKey.call(this, alg, extractable, keyUsages, function (err, key) {
                try {
                    if (err) {
                        cb(err, null);
                    }
                    else {
                        if (key.type === "public") {
                            key.usages = ["encrypt", "wrapKey"];
                        }
                        else {
                            key.usages = ["decrypt", "unwrapKey"];
                        }
                        cb(null, key);
                    }
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaOAEP.exportKey = function (format, key, cb) {
        try {
            _super.exportKey.call(this, format, key, function (err, data) {
                if (err)
                    return cb(err, null);
                try {
                    if (format === "jwk") {
                        var jwk = data;
                        // set alg
                        var md_size = /(\d+)$/.exec(key.algorithm.hash.name)[1];
                        jwk.alg = "RSA-OAEP";
                        if (md_size !== "1") {
                            jwk.alg += "-" + md_size;
                        }
                        jwk.ext = true;
                        if (key.type === "public") {
                            jwk.key_ops = ["encrypt", "wrapKey"];
                        }
                        else {
                            jwk.key_ops = ["decrypt", "unwrapKey"];
                        }
                        cb(null, jwk);
                    }
                    else
                        cb(null, data);
                }
                catch (e) {
                    cb(e, null);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaOAEP.encrypt = function (alg, key, data, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPublicKey(key);
            var _alg = this.wc2ssl(key.algorithm);
            var nkey = key.native;
            var label = null;
            if (alg.label) {
                label = new Buffer(alg.label);
            }
            nkey.RsaOaepEncDec(_alg, data, label, false, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaOAEP.decrypt = function (alg, key, data, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPrivateKey(key);
            var _alg = this.wc2ssl(key.algorithm);
            var nkey = key.native;
            var label = null;
            if (alg.label) {
                label = new Buffer(alg.label);
            }
            nkey.RsaOaepEncDec(_alg, data, label, true, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaOAEP.wrapKey = function (key, wrappingKey, algorithm, cb) {
        try {
            this.checkAlgorithmIdentifier(algorithm);
            this.checkAlgorithmHashedParams(algorithm);
            this.checkSecretKey(key);
            this.checkPublicKey(wrappingKey);
            var _alg_1 = this.wc2ssl(algorithm);
            var nkey_1 = wrappingKey.native;
            var nAesKey = key.native;
            nAesKey.export(function (err, data) {
                if (err) {
                    cb(err, null);
                }
                else {
                    nkey_1.RsaOaepEncDec(_alg_1, data, null, false, cb);
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaOAEP.unwrapKey = function (wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedAlgorithm, extractable, keyUsages, cb) {
        try {
            this.checkAlgorithmIdentifier(unwrapAlgorithm);
            this.checkAlgorithmHashedParams(unwrapAlgorithm);
            this.checkPrivateKey(unwrappingKey);
            var _alg = this.wc2ssl(unwrapAlgorithm);
            // convert unwrappedAlgorithm to PKCS11 Algorithm
            var AlgClass = null;
            switch (unwrappedAlgorithm.name) {
                // case aes.ALG_NAME_AES_CTR:
                // case aes.ALG_NAME_AES_CMAC:
                // case aes.ALG_NAME_AES_CFB:
                // case aes.ALG_NAME_AES_KW:
                case aes.ALG_NAME_AES_CBC:
                    aes.Aes.checkKeyGenParams(unwrappedAlgorithm);
                    AlgClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    aes.Aes.checkKeyGenParams(unwrappedAlgorithm);
                    AlgClass = aes.AesGCM;
                    break;
                default:
                    throw new Error("Unsupported algorithm in use");
            }
            var label = unwrapAlgorithm.label;
            if (!label)
                label = new Buffer(0);
            if (!Buffer.isBuffer(label))
                label = new Buffer(label);
            unwrappingKey.native.RsaOaepEncDec(_alg, wrappedKey, label, true, function (err, rawKey) {
                if (err) {
                    cb(err, null);
                }
                else {
                    native.AesKey.import(rawKey, function (err, nkey) {
                        if (err) {
                            cb(err, null);
                        }
                        else {
                            cb(null, new key.CryptoKey(nkey, unwrappedAlgorithm, "secret", extractable, keyUsages));
                        }
                    });
                }
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    RsaOAEP.ALGORITHM_NAME = ALG_NAME_RSA_OAEP;
    return RsaOAEP;
}(Rsa));
exports.RsaOAEP = RsaOAEP;
