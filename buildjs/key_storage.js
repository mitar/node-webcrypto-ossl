"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var error_1 = require("./error");
var native = require("./native");
var key_1 = require("./key");
var fs = require("fs");
var path = require("path");
var mkdirp = require("mkdirp");
var KeyStorageError = (function (_super) {
    __extends(KeyStorageError, _super);
    function KeyStorageError() {
        _super.apply(this, arguments);
    }
    return KeyStorageError;
}(error_1.WebCryptoError));
function jwkBufferToBase64(jwk) {
    var cpyJwk = jwk.keyJwk;
    for (var i in cpyJwk) {
        var attr = cpyJwk[i];
        if (Buffer.isBuffer(attr)) {
            cpyJwk[i] = attr.toString("base64");
        }
    }
    return jwk;
}
function jwkBase64ToBuffer(jwk) {
    var cpyJwk = jwk.keyJwk;
    var reserved = ["kty", "usage", "alg", "crv", "ext", "alg", "name"];
    for (var i in cpyJwk) {
        var attr = cpyJwk[i];
        if (reserved.indexOf(i) === -1 && typeof attr === "string") {
            try {
                var buf = new Buffer(attr, "base64");
                cpyJwk[i] = buf;
            }
            catch (e) { }
        }
    }
    return jwk;
}
var KeyStorage = (function () {
    function KeyStorage(directory) {
        this.directory = "";
        this.keys = {};
        this.directory = directory;
        if (!fs.existsSync(directory))
            this.createDirectory(directory);
        this.readDirectory();
    }
    KeyStorage.prototype.createDirectory = function (directory, flags) {
        mkdirp.sync(directory, flags);
    };
    KeyStorage.prototype.readFile = function (file) {
        if (!fs.existsSync(file))
            throw new KeyStorageError("File '" + file + "' is not exists");
        var ftext = fs.readFileSync(file, "utf8");
        var json = null;
        try {
            json = JSON.parse(ftext);
        }
        catch (e) {
            return null;
        }
        // check JSON structure
        if (json.algorithm && json.type && json.usages && json.name)
            return json;
        return null;
    };
    KeyStorage.prototype.readDirectory = function () {
        if (!this.directory)
            throw new KeyStorageError("KeyStorage directory is not set");
        this.keys = {}; // clear keys
        var items = fs.readdirSync(this.directory);
        for (var _i = 0, items_1 = items; _i < items_1.length; _i++) {
            var item = items_1[_i];
            if (item !== "." && item !== "..") {
                var file = path.join(this.directory, item);
                var stat = fs.statSync(file);
                if (stat.isFile) {
                    var key = this.readFile(file);
                    if (key)
                        this.keys[key.name] = key;
                }
            }
        }
    };
    KeyStorage.prototype.saveFile = function (key) {
        var json = JSON.stringify(key);
        fs.writeFileSync(path.join(this.directory, key.name + ".json"), json, {
            encoding: "utf8",
            flag: "w"
        });
    };
    Object.defineProperty(KeyStorage.prototype, "length", {
        get: function () {
            return Object.keys(this.keys).length;
        },
        enumerable: true,
        configurable: true
    });
    /**
     * Clears KeyStorage
     * - be careful, removes all files from selected directory
     */
    KeyStorage.prototype.clear = function () {
        if (!this.directory)
            return;
        this.keys = {}; // clear keys
        var items = fs.readdirSync(this.directory);
        for (var _i = 0, items_2 = items; _i < items_2.length; _i++) {
            var item = items_2[_i];
            if (item !== "." && item !== "..") {
                var file = path.join(this.directory, item);
                var stat = fs.statSync(file);
                if (stat.isFile) {
                    fs.unlinkSync(file);
                }
            }
        }
    };
    KeyStorage.prototype.getItemById = function (id) {
        return this.keys[id] || null;
    };
    KeyStorage.prototype.getItem = function (key) {
        var item = this.getItemById(key);
        if (!item)
            return null;
        item = jwkBase64ToBuffer(item);
        var res = null;
        var nativeKey = null;
        switch (item.type.toLowerCase()) {
            case "public":
                nativeKey = native.Key.importJwk(item.keyJwk, native.KeyType.PUBLIC);
                break;
            case "private":
                nativeKey = native.Key.importJwk(item.keyJwk, native.KeyType.PRIVATE);
                break;
            case "secret":
                throw new Error("Not implemented yet");
        }
        if (nativeKey) {
            res = new key_1.CryptoKey(nativeKey, item.algorithm, item.type, item.extractable, item.usages);
        }
        return res;
    };
    KeyStorage.prototype.key = function (index) {
        throw new Error("Not implemented yet");
    };
    KeyStorage.prototype.removeItem = function (key) {
        throw new Error("Not implemented yet");
    };
    KeyStorage.prototype.setItem = function (key, data) {
        var nativeKey = data.native;
        var jwk = null;
        switch (data.type.toLowerCase()) {
            case "public":
                jwk = nativeKey.exportJwk(native.KeyType.PUBLIC);
                break;
            case "private":
                jwk = nativeKey.exportJwk(native.KeyType.PRIVATE);
                break;
            case "secret":
                throw new Error("Not implemented yet");
        }
        if (jwk) {
            var item = {
                algorithm: data.algorithm,
                usages: data.usages,
                type: data.type,
                keyJwk: jwk,
                name: key,
                extractable: data.extractable
            };
            item = jwkBufferToBase64(item);
            this.saveFile(item);
            this.keys[key] = item;
        }
    };
    return KeyStorage;
}());
exports.KeyStorage = KeyStorage;
