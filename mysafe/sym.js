/** @fileOverview working with symmetrical keys
 *
 * @author (c)2021 Petr Vanek, petr@fotoventus.cz
 */


 "use strict";


/**
 * generate symmetric key 
 * @param {int} keyLen bit length
 * @param {string} alg alg. name
 * @returns 
 */
 mysafe.sym.generateKey =   async function (keyLen=256, alg='AES-GCM') {
    return  window.crypto.subtle.generateKey({ name: alg, length: keyLen}, true, ['encrypt', 'decrypt']);
}

/**
 * 
 * @returns 
 */
mysafe.sym.generateSalt =  function (saltSize=16) {
  var salt = new Uint8Array(saltSize); 
  window.crypto.getRandomValues(salt);
  return salt;
}

mysafe.sym.deriveKey =  async function (originKey, salt, keyLen, hmacAlg = 'SHA-512') {
    const info = new ArrayBuffer(0);
    var okm = await mysafe.hash.hkdfDerivation(originKey, salt, info, keyLen, hmacAlg );
    return okm;
}

mysafe.sym.exportKeyBytes =   async function (secretKey) {
  const k = crypto.subtle.exportKey('raw', secretKey);
  return k;
}

mysafe.sym.exportKey2Hex =   async function (secretKey) {
    const k = await mysafe.sym.exportKeyBytes(secretKey);
    const exporteddKey =  mysafe.utils.bytes2Hex(k);
    return exporteddKey;
}

mysafe.sym.exportKey2B64 =   async function (secretKey) {
  const k = await mysafe.sym.exportKeyBytes(secretKey);
  const exporteddKey =  mysafe.utils.bytes2Base64(k);
  return exporteddKey;
}

mysafe.sym.getKeyFromBytes =  async function (importedKey, aesAlg = 'AES-GCM') {
  let key =  crypto.subtle.importKey('raw', importedKey , aesAlg, true, ['encrypt', 'decrypt']); 
  return key;
}

mysafe.sym.getKeyFromHex =  async function (hex) {
    const importedKey =  mysafe.utils.hex2Bytes(hex);
    let key =  mysafe.sym.getKeyFromBytes(importedKey); 
    return key;
}

mysafe.sym.getKeyFromB64 =   async function (hex) {
  const importedKey =  mysafe.utils.base642Bytes(hex);
  let key =  mysafe.sym.getKeyFromBytes(importedKey); 
  return key;
}

/**
 * derive ECDH key
 * @param {*} privateKey 
 * @param {*} publicKey 
 * @param {*} numbits 
 * @returns 
 */
mysafe.sym.ecdhDerivation =   async function (privateKey, publicKey, numbits = 528, ecCurveName = 'P-521') {

   return  window.crypto.subtle.deriveBits({
        name: "ECDH",
        namedCurve: ecCurveName, 
        public: publicKey, 
    },
    privateKey, 
    numbits  
    );
  }

  mysafe.sym.saltedPartyKey =  async function (privateKey, publicKey, salt, aesKeyLen = 256) {

    const partyKey = await mysafe.sym.ecdhDerivation(privateKey, publicKey); 
    var okm = await mysafe.hash.hkdfSha512(
        partyKey,  // IKM
        salt, // salt
        new Uint8Array(0),     //info
         aesKeyLen // L
        );
    return okm;
  }

  mysafe.sym.saltedPartyKeyFromEcdh =  async function (ecdhKey, salt, aesKeyLen = 256) {

    var okm = await mysafe.hash.hkdfSha512(
        ecdhKey,  // IKM
        salt, // salt
        new Uint8Array(0),     //info
        aesKeyLen // L
        );
    return okm;
  }

mysafe.sym.pbkdf2DerivationKey = async function(passphraseKey, saltBuffer, iterations, hashDef =  "SHA-256", aesAlg = 'AES-GCM', aesKeyLen = 256) {
   const key = await window.crypto.subtle.importKey(
        'raw', 
        passphraseKey, 
        {name: 'PBKDF2'}, 
        false, 
        ['deriveBits', 'deriveKey']
      );


  var rc =  window.crypto.subtle.deriveKey(
    { "name": 'PBKDF2',
      "salt": saltBuffer,
      "iterations": iterations,
      "hash": hashDef
    },
    key,
    { "name": aesAlg, "length": aesKeyLen },
    true,
    [ "encrypt", "decrypt" ]
  );

  return rc;
}
  
mysafe.sym.pbkdf2DerivationBits = async function(passphraseKey, saltBuffer, iterations, bitslen, hashDef =  "SHA-256") {
    const key = await window.crypto.subtle.importKey(
         'raw', 
         passphraseKey, 
         {name: 'PBKDF2'}, 
         false, 
         ['deriveBits', 'deriveKey']
       );
 
 
       const derivedBits = await window.crypto.subtle.deriveBits(
        {
          "name": "PBKDF2",
          salt: saltBuffer,
          "iterations": iterations,
          "hash": hashDef
        },
        key,
        bitslen
      );
 
   return derivedBits;
 }
   

 mysafe.sym.pbkdf2DerivationBits2 = async function(passphraseKey, saltBuffer, iterations, bitslen, hashDef =  "SHA-256") {

  var out = new Uint8Array(0);
  var block = new (saltBuffer.constructor)(saltBuffer.length + 4);
  block.set(saltBuffer, 0); 
  const len = bitslen / 8;
  var num = 0;
  var md, prev, i, j;
  while (out.length < len) {
    num++;
    cryptocom.misc.uint322array(block, num, saltBuffer.length );
    prev = await cryptocom.hashes.hmac(passphraseKey, block, hashDef);
    md = new Uint8Array(prev);
    i = 0;
    while (++i < iterations) {
      prev = new Uint8Array(await cryptocom.hashes.hmac(passphraseKey, prev, hashDef));
      j = -1;
      while (++j < prev.length) {
        md[j] ^= prev[j]
      }
    }
    out = cryptocom.misc.concatTypedArrays(out, md);
  }

  return  out.slice(0, len).buffer;
 }