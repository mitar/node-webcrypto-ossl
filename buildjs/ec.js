"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var aes = require("./aes");
var alg = require("./alg");
var key_1 = require("./key");
var native = require("./native");
var base64url = require("base64url");
var ALG_NAME_ECDH = "ECDH";
var ALG_NAME_ECDSA = "ECDSA";
var HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];
function nc2ssl(nc) {
    var _namedCurve = "";
    switch (nc.toUpperCase()) {
        case "P-192":
            _namedCurve = "secp192r1";
            break;
        case "P-256":
            _namedCurve = "secp256r1";
            break;
        case "P-384":
            _namedCurve = "secp384r1";
            break;
        case "P-521":
            _namedCurve = "secp521r1";
            break;
        default:
            throw new Error("Unsupported namedCurve in use");
    }
    return native.EcNamedCurves[_namedCurve];
}
var Ec = (function (_super) {
    __extends(Ec, _super);
    function Ec() {
        _super.apply(this, arguments);
    }
    Ec.generateKey = function (alg, extractable, keyUsages, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenParams(alg);
            var namedCurve = nc2ssl(alg.namedCurve);
            native.Key.generateEc(namedCurve, function (err, key) {
                cb(null, {
                    "privateKey": new key_1.CryptoKey(key, alg, "private", extractable, keyUsages),
                    "publicKey": new key_1.CryptoKey(key, alg, "public", extractable, keyUsages)
                });
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    Ec.importKey = function (format, keyData, algorithm, extractable, keyUsages, cb) {
        try {
            this.checkKeyType(format);
            this.checkAlgorithmIdentifier(algorithm);
            switch (format) {
                case "pkcs8":
                    native.Key.importPkcs8(keyData, function (err, key) {
                        if (!err) {
                            var ec = new key_1.CryptoKey(key, algorithm, "private", extractable, keyUsages);
                            cb(null, ec);
                        }
                        else
                            cb(err, null);
                    });
                    break;
                case "spki":
                    native.Key.importSpki(keyData, function (err, key) {
                        if (!err) {
                            var ec = new key_1.CryptoKey(key, algorithm, "public", extractable, keyUsages);
                            cb(null, ec);
                        }
                        else
                            cb(err, null);
                    });
                    break;
                case "jwk":
                    // prepare data
                    var jwk = {
                        kty: "EC",
                        key_ops: [],
                        crv: "",
                        x: null,
                        y: null
                    };
                    var inJwk = keyData;
                    jwk.crv = nc2ssl(inJwk.crv);
                    jwk.x = new Buffer(base64url.decode(inJwk.x, "binary"), "binary");
                    jwk.y = new Buffer(base64url.decode(inJwk.y, "binary"), "binary");
                    var key_type_1 = native.KeyType.PUBLIC;
                    if (inJwk.d) {
                        key_type_1 = native.KeyType.PRIVATE;
                        jwk.d = new Buffer(base64url.decode(inJwk.d, "binary"), "binary");
                    }
                    native.Key.importJwk(jwk, key_type_1, function (err, key) {
                        if (!err) {
                            var ec = new key_1.CryptoKey(key, algorithm, key_type_1 === native.KeyType.PRIVATE ? "private" : "public", extractable, keyUsages);
                            cb(null, ec);
                        }
                        else
                            cb(err, null);
                    });
                    break;
                default:
                    throw new Error("Ec::ImportKey: Wrong import key format");
            }
        }
        catch (e) {
            cb(e, null);
        }
    };
    Ec.exportKey = function (format, key, cb) {
        try {
            this.checkKeyType(format);
            var nkey = key.native;
            switch (format) {
                case "spki":
                    nkey.exportSpki(cb);
                    break;
                case "pkcs8":
                    nkey.exportPkcs8(cb);
                    break;
                case "jwk":
                    // create jwk  
                    var pubJwk_1 = {
                        kty: "EC",
                        crv: key.algorithm.namedCurve,
                        key_ops: [],
                        x: null,
                        y: null,
                        ext: true
                    };
                    var key_type_2 = key.type === "public" ? native.KeyType.PUBLIC : native.KeyType.PRIVATE;
                    nkey.exportJwk(key_type_2, function (err, jwk) {
                        if (!err) {
                            try {
                                pubJwk_1.x = base64url(jwk.x);
                                pubJwk_1.y = base64url(jwk.y);
                                if (key_type_2 === native.KeyType.PRIVATE)
                                    pubJwk_1.d = base64url(jwk.d);
                                cb(null, pubJwk_1);
                            }
                            catch (e) {
                                cb(e, null);
                            }
                        }
                        else
                            cb(err, null);
                    });
                    break;
                default:
                    throw new Error("Ec::ExportKey: Wrong export key format");
            }
        }
        catch (e) {
            cb(e, null);
        }
    };
    Ec.checkKeyGenParams = function (alg) {
        this.checkAlgorithmParams(alg);
    };
    Ec.checkAlgorithmHashedParams = function (alg) {
        _super.checkAlgorithmHashedParams.call(this, alg);
        var _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknown hash algorithm in use");
    };
    Ec.checkAlgorithmParams = function (alg) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.namedCurve)
            throw new TypeError("EcParams: namedCurve: Missing required property");
        switch (alg.namedCurve.toUpperCase()) {
            case "P-192":
            case "P-256":
            case "P-384":
            case "P-521":
                break;
            default:
                throw new TypeError("EcParams: namedCurve: Wrong value. Can be P-192, P-256, P-384, or P-521");
        }
        alg.namedCurve = alg.namedCurve.toUpperCase();
    };
    Ec.wc2ssl = function (alg) {
        throw new Error("Not realized");
    };
    return Ec;
}(alg.AlgorithmBase));
exports.Ec = Ec;
var Ecdsa = (function (_super) {
    __extends(Ecdsa, _super);
    function Ecdsa() {
        _super.apply(this, arguments);
    }
    Ecdsa.wc2ssl = function (alg) {
        this.checkAlgorithmHashedParams(alg);
        // let _alg = "ecdsa-with-" + alg.hash.name.toUpperCase().replace("-", "");
        var _alg = alg.hash.name.toUpperCase().replace("-", "");
        return _alg;
    };
    Ecdsa.generateKey = function (alg, extractable, keyUsages, cb) {
        _super.generateKey.call(this, alg, extractable, keyUsages, function (err, keys) {
            if (!err) {
                keys.privateKey.usages = ["sign"];
                keys.publicKey.usages = ["verify"];
                cb(null, keys);
            }
            else
                cb(err, null);
        });
    };
    Ecdsa.sign = function (alg, key, data, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkAlgorithmHashedParams(alg);
            this.checkPrivateKey(key);
            var _alg = this.wc2ssl(alg);
            key.native.sign(_alg, data, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    Ecdsa.verify = function (alg, key, signature, data, cb) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkAlgorithmHashedParams(alg);
            this.checkPublicKey(key);
            var _alg = this.wc2ssl(alg);
            key.native.verify(_alg, data, signature, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    Ecdsa.exportKey = function (format, key, cb) {
        _super.exportKey.call(this, format, key, function (err, d) {
            if (!err) {
                if (format === "jwk") {
                    var jwk = d;
                    if (key.type === "public")
                        jwk.key_ops = ["verify"];
                    else
                        jwk.key_ops = ["sign"];
                    cb(null, jwk);
                }
                else
                    cb(null, d);
            }
            else
                cb(err, null);
        });
    };
    Ecdsa.ALGORITHM_NAME = ALG_NAME_ECDSA;
    return Ecdsa;
}(Ec));
exports.Ecdsa = Ecdsa;
var Ecdh = (function (_super) {
    __extends(Ecdh, _super);
    function Ecdh() {
        _super.apply(this, arguments);
    }
    Ecdh.generateKey = function (alg, extractable, keyUsages, cb) {
        _super.generateKey.call(this, alg, extractable, keyUsages, function (err, keys) {
            if (!err) {
                keys.privateKey.usages = ["deriveKey"];
                keys.publicKey.usages = [];
                cb(null, keys);
            }
            else
                cb(err, null);
        });
    };
    Ecdh.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages, cb) {
        try {
            this.checkAlgorithmParams(algorithm);
            this.checkPublicKey(algorithm.public);
            this.checkPrivateKey(baseKey);
            if (algorithm.public.algorithm.name !== "ECDH")
                throw new TypeError("ECDH::CheckAlgorithm: Public key is not ECDH");
            var type = "secret";
            switch (derivedKeyType.name.toLowerCase()) {
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    aes.AesCBC.checkKeyGenParams(derivedKeyType);
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    aes.AesGCM.checkKeyGenParams(derivedKeyType);
                    break;
                default:
                    throw new Error("derivedKeyType: Unknown Algorithm name in use");
            }
            // derive key
            baseKey.native.EcdhDeriveKey(algorithm.public.native, derivedKeyType.length, function (err, raw) {
                if (!err) {
                    native.AesKey.import(raw, function (err, key) {
                        if (!err) {
                            var aesKey = new key_1.CryptoKey(key, derivedKeyType, "secret", extractable, keyUsages);
                            cb(null, aesKey);
                        }
                        else
                            cb(err, null);
                    });
                }
                else
                    cb(err, null);
            });
        }
        catch (e) {
            cb(e, null);
        }
    };
    Ecdh.deriveBits = function (algorithm, baseKey, length, cb) {
        try {
            this.checkAlgorithmParams(algorithm);
            this.checkPublicKey(algorithm.public);
            this.checkPrivateKey(baseKey);
            if (algorithm.public.algorithm.name !== "ECDH")
                throw new TypeError("ECDH::CheckAlgorithm: Public key is not ECDH");
            if (!length)
                throw new TypeError("ECDH::DeriveBits: Wrong 'length' value");
            // derive bits
            baseKey.native.EcdhDeriveBits(algorithm.public.native, length, cb);
        }
        catch (e) {
            cb(e, null);
        }
    };
    Ecdh.exportKey = function (format, key, cb) {
        _super.exportKey.call(this, format, key, function (err, d) {
            if (!err) {
                if (format === "jwk") {
                    var jwk = d;
                    if (key.type === "public")
                        jwk.key_ops = [];
                    else
                        jwk.key_ops = ["deriveKey"];
                    cb(null, jwk);
                }
                else
                    cb(null, d);
            }
            else
                cb(err, null);
        });
    };
    Ecdh.checkAlgorithmParams = function (alg) {
        _super.checkAlgorithmParams.call(this, alg);
    };
    Ecdh.ALGORITHM_NAME = ALG_NAME_ECDH;
    return Ecdh;
}(Ec));
exports.Ecdh = Ecdh;
