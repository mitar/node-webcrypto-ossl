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
    WebCrypto.prototype.getRandomValues = function (array) {
        return crypto.randomBytes(array.byteLength);
    };
    return WebCrypto;
}());
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = WebCrypto;
