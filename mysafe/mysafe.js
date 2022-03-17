/** @fileOverview defining the namespace of individual parts of the library 
 *
 * @author (c)2021 Petr Vanek, petr@fotoventus.cz
 */

"use strict";
/**
 * The Vault Crypto Library, top-level namespace.
 * @namespace
 */

 var mysafe = {
  
   /**
    * working with asymmetric keys
    */
   asym: {},

   /** 
    * working with symmetrical keys
    */
   sym: {},

   /**
    * data encryption
    */
   enc: {},

   /**
    * set of HASH, HMAC and derivative functions
    */
   hash: {},

  /**
   * conversion and auxiliary functions
   */
  utils: {},
  
  /**
   * SCRYPT implementation RFC 7914
   */
  scrypt: {},

  /**
   * checks if the WebCrypto API is available
   */
  isReady :  function() {
    var crypto = window.crypto || window.msCrypto; // for IE 11
    if (crypto.subtle) return true;
    return false;
  }, 

  /**
   * set of used exceptions
   *  */   
  exception: {
  
    invalidData: function(message) {
      this.toString = function() { return "invalid data: " + this.message; };
      this.message = message;
    },
    
    invalidFormat: function(message) {
      this.toString = function() { return "invalid format: " + this.message; };
      this.message = message;
    }, 

    invalidParam: function(message) {
      this.toString = function() { return "invalid parameter: " + this.message; };
      this.message = message;
    }

  }
    
};