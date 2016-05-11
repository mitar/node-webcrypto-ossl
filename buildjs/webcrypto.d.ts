import * as iwc from "./iwebcrypto";
/**
 * PKCS11 with WebCrypto Interface
 */
export default class WebCrypto implements iwc.IWebCrypto {
    subtle: iwc.ISubtleCrypto;
    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    getRandomValues(array: any): any;
    /**
     * Constructor
     */
    constructor();
}
