"use strict";
var subtle = require("./subtle");
var crypto = require("crypto");
/**
 * PKCS11 with WebCrypto Interface
 */
var WebCrypto = (function () {
    /**
     * Constructor
     */
    function WebCrypto() {
        this.subtle = null;
        this.subtle = new subtle.SubtleCrypto();
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
//# sourceMappingURL=webcrypto.js.map