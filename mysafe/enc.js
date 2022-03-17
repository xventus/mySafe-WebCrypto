/** @fileOverview  functions for data encryption and decryption  
 *
 * @author (c)2021 Petr Vanek, petr@fotoventus.cz
 */


 "use strict";

/**
 * TAG gain from encrypted data (for AES-GCM)
 * 
 * @param {Uint8Array} encrypted 
 * @param {int} tagLength 
 * @returns tag
 */
mysafe.enc.getTag  = function(encrypted, tagLength) {
    if (tagLength === void 0) tagLength = 16;
    return encrypted.slice(encrypted.byteLength - ((tagLength + 7) >> 3))
}

/**
 * encrypt the data
 * @param {key} key 
 * @param {Uint8Array} plainMessage 
 * @param {int} ivLen length of the initialization vector
 * @param {string} alg the encryption algorithm used
 * @returns Uint8Array - data format [ IV | encrypted data | TAG]
 */
 mysafe.enc.encryptData =  async function (key, plainMessage, ivLen=12, alg='AES-GCM') {
    
    const iv = window.crypto.getRandomValues(new Uint8Array(ivLen));
    const encdata = await window.crypto.subtle.encrypt({ name: alg, iv: iv }, key, plainMessage);
    const  encUint8View = new Uint8Array(encdata); // encrypted data + TAG
    const messge = new Uint8Array(iv.length + encUint8View.length);
    messge.set(iv);
    messge.set(encUint8View, iv.length);

    return messge;
}

/**
 * decrypt data
 * @param {key} key 
 * @param {Uint8Array} encMessage data format [ IV | encrypted data | TAG]
 * @param {int} ivLen 
 * @param {string} alg 
 * @returns Uint8Array - plain message
 */
mysafe.enc.decryptData = async function (key, encMessage, ivLen=12, alg='AES-GCM') {
    try {
        var iv = encMessage.slice(0, ivLen);
        var data = encMessage.slice(ivLen, encMessage.length);
        var plain = await window.crypto.subtle.decrypt({ name:  alg, iv: iv }, key, data); 
    }
    catch(e) {
        throw new mysafe.exception.invalidData("Unable to decrypt:",e.message);
    }

    return plain;
}


