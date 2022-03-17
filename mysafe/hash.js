/** @fileOverview  HASH & HMAC
 *
 * @author (c)2021 Petr Vanek, petr@fotoventus.cz
 */

 "use strict";

/**
 * compute SHA512
 */
mysafe.hash.sha512 =  async function(data) {
    const k = await crypto.subtle.digest("SHA-512", data);
    return k ;
}

/**
 * compute SHA256
 */
mysafe.hash.sha256 =  async function(data) {
    const k = await crypto.subtle.digest("SHA-256", data);
    return k ;
}

/**
 * compute SHA1
 */
mysafe.hash.sha1 =  async function(data) {
    const k = await crypto.subtle.digest("SHA-1", data);
    return k ;
}

/**
 * compute HMAC
 * @param {Uint8Array} keyBytes 
 * @param {Uint8Array} data 
 * @param {string} alg name of alg. aka "SHA-512"....
 * @returns 
 */
mysafe.hash.hmac =  async function(keyBytes, data, alg) {
    let algorithm = { name: "HMAC", hash: alg };
    let key = await crypto.subtle.importKey("raw", keyBytes, algorithm, false, ["sign", "verify"]);
    let hmac = await crypto.subtle.sign(algorithm.name, key, data);
    return hmac;
}

/**
 * compute HMAC512
 * @param {Uint8Array} keyBytes 
 * @param {Uint8Array} data 
 * @returns 
 */
mysafe.hash.hmac512 =  async function(keyBytes, data) {
    return mysafe.hash.hmac(keyBytes, data, "SHA-512");
}

/**
 * compute HMAC256
 * @param {Uint8Array} keyBytes 
 * @param {Uint8Array} data 
 * @returns 
 */
mysafe.hash.hmac256 =  async function(keyBytes, data) {
    return mysafe.hash.hmac(keyBytes, data, "SHA-256");
}

/**
 * compute HMAC1
 * @param {Uint8Array} keyBytes 
 * @param {Uint8Array} data 
 * @returns 
 */
mysafe.hash.hmac1 =  async function(keyBytes, data) {
    return mysafe.hash.hmac(keyBytes, data, "SHA-1");
}

/**
 * HKDF derivation - RFC 5869 
 * @param {Uint8Array} key input keying material
 * @param {Uint8Array} saltdata optional salt value (a non-secret random value)
 * @param {Uint8Array} info optional context and application specific information
 * @param {int} bitLen number of bits requested per output
 * @param {string} hmac the hash algorithm used to derive the handle
 * @returns Uint8Array derivative key buffer
 */
mysafe.hash.hkdfDerivation =  async function(key, saltdata, info, bitLen, hmac) { 
    const keyin = await crypto.subtle.importKey(
        'raw', key, { name: 'HKDF' }, false,
        ['deriveKey', 'deriveBits']);
    
    const derived = await crypto.subtle.deriveBits(
        {
        name: 'HKDF',
        info: info,
        salt: saltdata,
        hash: hmac 
        },
        keyin,
        bitLen);  

        return derived;
}

/**
 * HKDF derivation -  - based on SHA256
 * @param {Uint8Array} key input keying material
 * @param {Uint8Array} saltdata optional salt value (a non-secret random value)
 * @param {Uint8Array} info optional context and application specific information
 * @param {int} bitLen number of bits requested per output
 * @returns Uint8Array derivative key buffer
 */
mysafe.hash.hkdfSha256 =  async function(key, saltdata, info, bitLen) {
    return mysafe.hash.hkdfDerivation(key, saltdata, info, bitLen, 'SHA-256');
}

/**
 * HKDF derivation - based on SHA512
 * @param {Uint8Array} key input keying material
 * @param {Uint8Array} saltdata optional salt value (a non-secret random value)
 * @param {Uint8Array} info optional context and application specific information
 * @param {int} bitLen number of bits requested per output
 * @returns Uint8Array derivative key buffer
 */
mysafe.hash.hkdfSha512 =  async function(key, saltdata, info, bitLen) {
    return mysafe.hash.hkdfDerivation(key, saltdata, info, bitLen, 'SHA-512');
}

