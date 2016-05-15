"use strict";
var native = require("./native");
var rsa = require("./rsa");
var aes = require("./aes");
var ec = require("./ec");
function prepare_algorithm(alg) {
    var _alg = { name: "" };
    if (typeof alg === "string") {
        _alg = { name: alg };
    }
    else {
        _alg = alg;
    }
    return _alg;
}
/**
 * Prepare array of data before it's using
 * @param data Array which must be prepared
 */
function prepare_data(data) {
    return (data instanceof ArrayBuffer || data instanceof Uint8Array) ? ab2b(data) : data;
}
/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value wich must be converted to Buffer
 */
function ab2b(ab) {
    var buf = new Uint8Array(ab);
    return new Buffer(buf);
}
/**
 * Converts Buffer to ArrayBuffer
 * @param b Buffer value wich must be converted to ArrayBuffer
 */
function b2ab(b) {
    return new Uint8Array(b).buffer;
}
;
var SubtleCrypto = (function () {
    function SubtleCrypto() {
    }
    SubtleCrypto.prototype.digest = function (algorithm, data) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var _data = prepare_data(data);
            var algName = _alg.name.toLowerCase();
            switch (algName) {
                case "sha-1":
                case "sha-224":
                case "sha-256":
                case "sha-384":
                case "sha-512":
                    native.Core.digest(algName.replace("-", ""), _data, function (err, digest) {
                        if (err)
                            reject(err);
                        else
                            resolve(new Uint8Array(digest).buffer);
                    });
                    break;
                default:
                    resolve(new Error("AlgorithmIdentifier: Unknown algorithm name"));
            }
        });
    };
    SubtleCrypto.prototype.generateKey = function (algorithm, extractable, keyUsages) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.generateKey(_alg, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    };
    SubtleCrypto.prototype.sign = function (algorithm, key, data) {
        var that = this;
        var _data = prepare_data(data);
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.sign(_alg, key, _data, function (err, sig) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(sig).buffer);
            });
        });
    };
    SubtleCrypto.prototype.verify = function (algorithm, key, signature, data) {
        var that = this;
        var _signature = prepare_data(signature);
        var _data = prepare_data(data);
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.verify(_alg, key, _signature, _data, function (err, valid) {
                if (err)
                    reject(err);
                else
                    resolve(valid);
            });
        });
    };
    SubtleCrypto.prototype.encrypt = function (algorithm, key, data) {
        var that = this;
        var _data = prepare_data(data);
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.encrypt(_alg, key, _data, function (err, buf) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(buf).buffer);
            });
        });
    };
    SubtleCrypto.prototype.decrypt = function (algorithm, key, data) {
        var that = this;
        var _data = prepare_data(data);
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.decrypt(_alg, key, _data, function (err, buf) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(buf).buffer);
            });
        });
    };
    SubtleCrypto.prototype.wrapKey = function (format, key, wrappingKey, algorithm) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.wrapKey(key, wrappingKey, _alg, function (err, buf) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(buf).buffer);
            });
        });
    };
    SubtleCrypto.prototype.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedAlgorithm, extractable, keyUsages) {
        var that = this;
        var _wrappedKey = prepare_data(wrappedKey);
        return new Promise(function (resolve, reject) {
            var _alg1 = prepare_algorithm(unwrapAlgorithm);
            var _alg2 = prepare_algorithm(unwrappedAlgorithm);
            var AlgClass = null;
            switch (_alg1.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.unwrapKey(_wrappedKey, unwrappingKey, _alg1, _alg2, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    };
    SubtleCrypto.prototype.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg1 = prepare_algorithm(algorithm);
            var _alg2 = prepare_algorithm(derivedKeyType);
            var AlgClass = null;
            switch (_alg1.name.toLowerCase()) {
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.deriveKey(_alg1, baseKey, _alg2, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    };
    SubtleCrypto.prototype.deriveBits = function (algorithm, baseKey, length) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            AlgClass.deriveBits(_alg, baseKey, length, function (err, dbits) {
                if (err)
                    reject(err);
                else
                    resolve(new Uint8Array(dbits).buffer);
            });
        });
    };
    SubtleCrypto.prototype.exportKey = function (format, key) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var KeyClass;
            switch (key.algorithm.name) {
                case rsa.RsaPKCS1.ALGORITHM_NAME:
                    KeyClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaOAEP.ALGORITHM_NAME:
                    KeyClass = rsa.RsaOAEP;
                    break;
                case aes.AesCBC.ALGORITHM_NAME:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.AesGCM.ALGORITHM_NAME:
                    KeyClass = aes.AesGCM;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME:
                    KeyClass = ec.Ecdsa;
                    break;
                case ec.Ecdh.ALGORITHM_NAME:
                    KeyClass = ec.Ecdh;
                    break;
                default:
                    throw new Error("ExportKey: Unsupported algorithm " + key.algorithm.name);
            }
            KeyClass.exportKey(format.toLocaleLowerCase(), key, function (err, data) {
                if (err)
                    reject(err);
                else if (Buffer.isBuffer(data)) {
                    var ubuf = new Uint8Array(data);
                    resolve(ubuf.buffer);
                }
                else
                    resolve(data);
            });
        });
    };
    SubtleCrypto.prototype.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var _data = prepare_data(keyData);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            if (format.toLocaleLowerCase() === "jwk") {
                if (Buffer.isBuffer(keyData)) {
                    throw new Error("ImportKey: keydData must be Object");
                }
                // copy input object
                var cpy = {};
                for (var i in _data) {
                    cpy[i] = _data[i];
                }
                _data = cpy;
            }
            AlgClass.importKey(format.toLocaleLowerCase(), _data, _alg, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    };
    return SubtleCrypto;
}());
exports.SubtleCrypto = SubtleCrypto;
