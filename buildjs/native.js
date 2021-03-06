"use strict";
var native = require("../build/Release/nodessl.node");
(function (EcNamedCurves) {
    EcNamedCurves[EcNamedCurves["secp112r1"] = 704] = "secp112r1";
    EcNamedCurves[EcNamedCurves["secp112r2"] = 705] = "secp112r2";
    EcNamedCurves[EcNamedCurves["secp128r1"] = 706] = "secp128r1";
    EcNamedCurves[EcNamedCurves["secp128r2"] = 707] = "secp128r2";
    EcNamedCurves[EcNamedCurves["secp160k1"] = 708] = "secp160k1";
    EcNamedCurves[EcNamedCurves["secp160r1"] = 709] = "secp160r1";
    EcNamedCurves[EcNamedCurves["secp160r2"] = 710] = "secp160r2";
    EcNamedCurves[EcNamedCurves["secp192r1"] = 409] = "secp192r1";
    EcNamedCurves[EcNamedCurves["secp192k1"] = 711] = "secp192k1";
    EcNamedCurves[EcNamedCurves["secp224k1"] = 712] = "secp224k1";
    EcNamedCurves[EcNamedCurves["secp224r1"] = 713] = "secp224r1";
    EcNamedCurves[EcNamedCurves["secp256k1"] = 714] = "secp256k1";
    EcNamedCurves[EcNamedCurves["secp256r1"] = 415] = "secp256r1";
    EcNamedCurves[EcNamedCurves["secp384r1"] = 715] = "secp384r1";
    EcNamedCurves[EcNamedCurves["secp521r1"] = 716] = "secp521r1";
    EcNamedCurves[EcNamedCurves["sect113r1"] = 717] = "sect113r1";
    EcNamedCurves[EcNamedCurves["sect113r2"] = 718] = "sect113r2";
    EcNamedCurves[EcNamedCurves["sect131r1"] = 719] = "sect131r1";
    EcNamedCurves[EcNamedCurves["sect131r2"] = 720] = "sect131r2";
    EcNamedCurves[EcNamedCurves["sect163k1"] = 721] = "sect163k1";
    EcNamedCurves[EcNamedCurves["sect163r1"] = 722] = "sect163r1";
    EcNamedCurves[EcNamedCurves["sect163r2"] = 723] = "sect163r2";
    EcNamedCurves[EcNamedCurves["sect193r1"] = 724] = "sect193r1";
    EcNamedCurves[EcNamedCurves["sect193r2"] = 725] = "sect193r2";
    EcNamedCurves[EcNamedCurves["sect233k1"] = 726] = "sect233k1";
    EcNamedCurves[EcNamedCurves["sect233r1"] = 727] = "sect233r1";
    EcNamedCurves[EcNamedCurves["sect239k1"] = 728] = "sect239k1";
    EcNamedCurves[EcNamedCurves["sect283k1"] = 729] = "sect283k1";
    EcNamedCurves[EcNamedCurves["sect283r1"] = 730] = "sect283r1";
    EcNamedCurves[EcNamedCurves["sect409k1"] = 731] = "sect409k1";
    EcNamedCurves[EcNamedCurves["sect409r1"] = 732] = "sect409r1";
    EcNamedCurves[EcNamedCurves["sect571k1"] = 733] = "sect571k1";
    EcNamedCurves[EcNamedCurves["sect571r1"] = 734] = "sect571r1";
})(exports.EcNamedCurves || (exports.EcNamedCurves = {}));
var EcNamedCurves = exports.EcNamedCurves;
(function (RsaPublicExponent) {
    RsaPublicExponent[RsaPublicExponent["RSA_3"] = 0] = "RSA_3";
    RsaPublicExponent[RsaPublicExponent["RSA_F4"] = 1] = "RSA_F4";
})(exports.RsaPublicExponent || (exports.RsaPublicExponent = {}));
var RsaPublicExponent = exports.RsaPublicExponent;
(function (KeyType) {
    KeyType[KeyType["PUBLIC"] = 0] = "PUBLIC";
    KeyType[KeyType["PRIVATE"] = 1] = "PRIVATE";
})(exports.KeyType || (exports.KeyType = {}));
var KeyType = exports.KeyType;
module.exports.Key = native.Key;
module.exports.Core = native.Core;
module.exports.AesKey = native.AesKey;
