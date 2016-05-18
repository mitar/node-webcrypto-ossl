"use strict";
var subtle = require("./subtle");
var crypto = require("crypto");
var key_storage_1 = require("./key_storage");
/**
 * OpenSSL with WebCrypto Interface
 */
var WebCrypto = (function () {
    /**
     * Constructor
     */
    function WebCrypto(options) {
        this.keyStorage = null;
        this.subtle = null;
        this.subtle = new subtle.SubtleCrypto();
        if (options && options.directory)
            this.keyStorage = new key_storage_1.KeyStorage(options.directory);
    }
    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    // Based on: https://github.com/KenanY/get-random-values
    WebCrypto.prototype.getRandomValues = function (typedArray) {
        if (typedArray.byteLength > 65536) {
            var error = new Error();
            error.code = 22;
            error.message = 'Failed to execute \'getRandomValues\' on \'Crypto\': The ' +
                'ArrayBufferView\'s byte length (' + typedArray.byteLength + ') exceeds the ' +
                'number of bytes of entropy available via this API (65536).';
            error.name = 'QuotaExceededError';
            throw error;
        }
        var bytes = crypto.randomBytes(typedArray.byteLength);
        typedArray.set(bytes);
        return typedArray;
    };
    return WebCrypto;
}());
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = WebCrypto;
