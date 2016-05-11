"use strict";
var CryptoKey = (function () {
    function CryptoKey(key, alg, type, extractable, keyUsages) {
        this.usages = [];
        this.native_ = key;
        this.extractable = extractable;
        this.algorithm = alg;
        // set key type
        this.type = type;
        // set key usages
        this.usages = keyUsages;
    }
    Object.defineProperty(CryptoKey.prototype, "native", {
        get: function () {
            return this.native_;
        },
        enumerable: true,
        configurable: true
    });
    return CryptoKey;
}());
exports.CryptoKey = CryptoKey;
//# sourceMappingURL=key.js.map