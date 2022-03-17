/** @fileOverview   asymmetric cryptography
 *
 * @author (c)2021 Petr Vanek, petr@fotoventus.cz
 */


 "use strict";



/**
 * generates an ECC key pair with ECDSA key usage
 * @param {string} curve  name of curve, can be "P-256", "P-384", "P-521"
 * @returns key pair
 */
mysafe.asym.generateECDSA =  async function(curve='P-521') {
   
    var k = await window.crypto.subtle.generateKey(
       {
        name: 'ECDSA',
        namedCurve: curve    
       }, true, ['sign', 'verify']);
    
    return k;
}


/**
 *  Export public key into SPKI format into array of bytes
 * @param {*} key 
 * @returns 
 */
mysafe.asym.exportPublicKey2Bytes =   async function (key) {
    const k = await  window.crypto.subtle.exportKey( 'spki', (key.type == 'public') ? key : key.publicKey);
    return k;
}


/**
 *  Export public key into SPKI format as HEX string
 * @param {*} key 
 * @returns 
 */
mysafe.asym.exportPublicKey2Hex =   async function (key) {
    const k = await  mysafe.asym.exportPublicKey2Bytes(key);
    const exporteddKey =  mysafe.utils.bytes2Hex(k);
    return exporteddKey;
}

/**
 *  Export public key into SPKI format as BASE64 string
 * @param {*} key 
 * @returns 
 */
mysafe.asym.exportPublicKey2B64 =   async function (key) {
    const k = await  mysafe.asym.exportPublicKey2Bytes(key);
    const exporteddKey =  mysafe.utils.bytes2Base64(k);
    return exporteddKey;
}


/**
 * Export private key in PKCS#8 format as array
 * @param {*} key 
 * @returns 
 */
mysafe.asym.exportPrivateKey2Bytes =   async function (key) {
    const k = await window.crypto.subtle.exportKey( 'pkcs8', (key.type == 'private') ? key : key.privateKey);
    return k;
}

/**
 * Export private key in PKCS#8 format as HEX string
 * @param {*} key 
 * @returns 
 */
mysafe.asym.exportPrivateKey2Hex =   async function (key) {
    const k = await mysafe.asym.exportPrivateKey2Bytes(key);
    const exporteddKey =  mysafe.utils.bytes2Hex(k);
    return exporteddKey;
}


/**
 * Export private key in PKCS#8 format as BASE64 string
 * @param {*} key 
 * @returns 
 */
mysafe.asym.exportPrivateKey2B64 =   async function (key) {
    const k = await mysafe.asym.exportPrivateKey2Bytes(key);
    const exporteddKey =  mysafe.utils.bytes2Base64(k);
    return exporteddKey;
}


/**
 * import private key form byte array, imported key has ECDSA key usage 
 * @param {*} importkey PKCS8# format required, byte array
 * @returns 
 */
mysafe.asym.importPrivateFromBytes = async function (importkey, curve='P-521') {
    const k =  crypto.subtle.importKey(
        'pkcs8',
        importkey,
        {
            name: 'ECDSA',
            namedCurve: curve
        },
        true,
        ["sign"]
    );
    return k;
}

/**
 * import private key,  imported key has ECDSA key usage 
 * @param {string} importkey PKCS8#  as HEX string
 * @returns 
 */
mysafe.asym.importPrivateFromHex = async function (indata, curve='P-521') {
    const importkey =  mysafe.utils.hex2Bytes(indata);
    const k =  mysafe.asym.importPrivateFromBytes(importkey, curve);
    return k;
}

/**
 * import private key,  imported key has ECDSA key usage 
 * @param {string} importkey PKCS8#  as BASE64 string
 * @returns 
 */
mysafe.asym.importPrivateFromB64 = async function (indata, curve='P-521') {
    const importkey =  mysafe.utils.base642Bytes(indata);
    const k =  mysafe.asym.importPrivateFromBytes(importkey, curve);
    return k;
}


/**
 * import PUBLIC Key with ECDSA key usage
 * @param {*} importkey - spki form as byte array
 * @returns 
 */
mysafe.asym.importPublicFromBytes = async function (importkey, curve='P-521') {
    const k =  crypto.subtle.importKey(
        'spki',
        importkey,
        {
            name: 'ECDSA',
            namedCurve: curve
        },
        true,
        [ "verify"]
    );
    return k;
}

/**
 * import PUBLIC Key with ECDSA key usage
 * @param {string} importkey - spki form as HEX string
 * @returns 
 */
mysafe.asym.importPublicFromHex = async function (indata, curve='P-521') {
    const importkey =  mysafe.utils.hex2Bytes(indata);
    const k =  mysafe.asym.importPublicFromBytes(importkey, curve);
    return k;
}

/**
 * import PUBLIC Key with ECDSA key usage
 * @param {string} importkey - spki form as BASE64 string
 * @returns 
 */
mysafe.asym.importPublicFromB64 = async function (indata, curve='P-521') {
    const importkey =  mysafe.utils.base642Bytes(indata);
    const k =  mysafe.asym.importPublicFromBytes(importkey, curve);
    return k;
}


/**
 * Import private key, with ECDH key usage
 * @param {*} importkey - byte array, key in PKCS#8 format 
 * @returns 
 */
mysafe.asym.importPrivateFromBytesECDH = async function (importkey, curve='P-521') {
    const k =  crypto.subtle.importKey(
        'pkcs8',
        importkey,
        {
            name: 'ECDH',
            namedCurve: curve 
        },
        true,
        ["deriveKey", "deriveBits"] 
    );
    return k;
}

/**
 * Import private key, with ECDH key usage
 * @param {string} importkey -  key in PKCS#8 format as HEX string 
 * @returns 
 */
mysafe.asym.importPrivateFromHexECDH = async function (indata, curve='P-521') {
    const importkey =  mysafe.utils.hex2Bytes(indata);
    const k =  mysafe.asym.importPrivateFromBytesECDH(importkey, curve);
    return k;
}

/**
 * Import private key, with ECDH key usage
 * @param {string} importkey -  key in PKCS#8 format as BASE64 string 
 * @returns 
 */
mysafe.asym.importPrivateFromB64ECDH = async function (indata, curve='P-521') {
    const importkey =  mysafe.utils.base642Bytes(indata);
    const k =  mysafe.asym.importPrivateFromBytesECDH(importkey, curve);
    return k;
}


/**
 * import public key with ECDH key usage
 * @param {*} importkey - array of bytes, PKCS#8 format
 * @returns 
 */
mysafe.asym.importPublicFromBytesECDH = async function (importkey, curve='P-521') {
   
    const k =  crypto.subtle.importKey(
        'spki',
        importkey,
        {
            name: 'ECDH',
            namedCurve: curve
        },
        true,
        [] 
    );
    return k;
}

/**
 * import public key with ECDH key usage
 * @param {string} importkey -  PKCS#8 format - hex string
 * @returns 
 */
mysafe.asym.importPublicFromHexECDH = async function (indata, curve='P-521') {
    const importkey =  mysafe.utils.hex2Bytes(indata);
    const k =  mysafe.asym.importPublicFromBytesECDH(importkey, curve);
    return k;
}

/**
 * import public key with ECDH key usage
 * @param {string} importkey -PKCS#8 format - BASE64 string
 * @returns 
 */
mysafe.asym.importPublicFromB64ECDH = async function (indata, curve='P-521') {
    const importkey =  mysafe.utils.base642Bytes(indata);
    const k =  mysafe.asym.importPublicFromBytesECDH(importkey, curve);
    return k;
}

/**
 * convert key usage ECDSA to ECC - private key
 * @param {privateKey} privateDsa 
 * @returns 
 */
mysafe.asym.privateDSA2ECD = async function (privateDsa, curve='P-521') {
    const expK = await mysafe.asym.exportPrivateKey2Bytes(privateDsa);
    var k = mysafe.asym.importPrivateFromBytesECDH(expK, curve);
    return k;
}

/**
 * convert key usage ECDSA to ECC - public key
 * @param {publicKey} publicteDsa 
 * @returns 
 */
mysafe.asym.publicDSA2ECD = async function (publicteDsa, curve='P-521') {
    const expK = await mysafe.asym.exportPublicKey2Bytes(publicteDsa);
    var k = mysafe.asym.importPublicFromBytesECDH(expK, curve);
    return k;
}