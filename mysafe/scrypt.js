/** @fileOverview  SCRYPT implementation
 * implementation based on rfc7914
 * 
 * @author (c)2021 Petr Vanek, petr@fotoventus.cz
 */

 "use strict";

 /**
  * copying between fields
  * @param {*} src source array
  * @param {*} srcFrom  the position of the source field from where it is copied
  * @param {*} dst target array
  * @param {*} dstFrom  position in the target field, where to copy 
  */
mysafe.scrypt.cpyRegion = function (src, srcFrom, dst, dstFrom) {
    const len =  (src.length - srcFrom);
    for (var i = 0; i < len; i++) dst[dstFrom + i] = src[srcFrom + i] | 0;
  };
  
  /**
   * XOR between arrays
   * @param {*} src source array
   * @param {*} srcFrom the position of the source field from where it is XORed
   * @param {*} dst target array
   * @param {*} dstFrom position in the target field (XORed with source)
   * @param {*} len optional length parameter 
   */
 mysafe.scrypt.xorRegion = function(src, srcFrom, dst, dstFrom, len) {
    len = len || (src.length - srcFrom);
    for (var i = 0; i < len; i++) { 
        dst[dstFrom + i] = ( src[srcFrom + i] ^ dst[dstFrom + i] ) | 0; 
    }
  };
  
  /**
   * blockMix
   * @param {*} blocks 
   * @returns 
   */
 mysafe.scrypt.blockMix = function(blocks) {
    var X = blocks.slice(-16),
        out = [],
        len = blocks.length / 16;
  
    for (var i = 0; i < len; i++) {
       mysafe.scrypt.xorRegion(blocks, 16 * i, X, 0, 16);
       mysafe.scrypt.salsa20Word(X, 8);
  
      if ((i & 1) == 0) {
       mysafe.scrypt.cpyRegion(X, 0, out, 8 * i);
      } else {
       mysafe.scrypt.cpyRegion(X, 0, out, 8 * (i^1 + len));
      }
    }
  
    return out;
  };
  
  /**
   * ROMix
   * @param {*} B 
   * @param {*} N 
   * @returns 
   */
 mysafe.scrypt.scryptROMix = function(B, N) {
    var V = [];
    var X = B.slice(0);
          
    for (var i = 0; i < N; i++) {
      V.push(X.slice(0));
      X =mysafe.scrypt.blockMix(X);
    }
  
    for (i = 0; i < N; i++) {
      var j = X[X.length - 16] & (N - 1);
     mysafe.scrypt.xorRegion(V[j], 0, X, 0);
      X =mysafe.scrypt.blockMix(X);
    }

    return X;
  };

/**
 * Salsa20/8 Core is a round-reduced variant of the Salsa20 Core.  
 * It is a hash function from 64-octet strings to 64-octet strings
 * @param {*} word 
 * @param {*} rounds 
 */
 mysafe.scrypt.salsa20Word = function (word, rounds) {
    var R = function(a, b) { return (a << b) | (a >>> (32 - b)); };
    var x = word.slice(0);
  
    for (var i = rounds; i > 0; i -= 2) {
      x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
      x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
      x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
      x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
      x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
      x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
      x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
      x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
      x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
      x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
      x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
      x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
      x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
      x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
      x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
      x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
    }
  
    for (i = 0; i < 16; i++) word[i] = x[i]+word[i];
  };
  

 
 /**
  * derivation of the handle data from the password
  * @param {Uint8Array} password human-chosen password
  * @param {Uint8Array} salt   randomly generated
  * @param {int} N  CPU/Memory cost parameter (must be larger than 1, a power of 2, and less than
  *                 2^(128 * r / 8))
  * @param {int} r block size (affects memory and CPU usage)
  * @param {int} p parallelization parameter  =< ((2^32-1) * 32) / (128 * r)
  * @param {int} length length in bits of the key to be derived  =< (2^32 - 1) * 32
  * @param {string} alg  - optional - hash algoritm
  * @returns 
  */
mysafe.scrypt.scryptBits =  async function (password, salt, N, r, p, length, alg='SHA-256') {
 
    const bl = await mysafe.sym.pbkdf2DerivationBits(password, salt, 1, p * 128 * r * 8, alg);
    var B = new Uint32Array(bl);
    var len = B.length / p;
  
    for (var i = 0; i < p; i++) {
      var block = B.slice(i * len, (i + 1) * len);
     mysafe.scrypt.cpyRegion(mysafe.scrypt.scryptROMix(block, N), 0, B, i * len);
    }
  
    return mysafe.sym.pbkdf2DerivationBits(password, B, 1, length, alg);  
  };
  
  
  
  

 