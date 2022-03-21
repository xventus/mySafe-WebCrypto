/** @fileOverview basic conversion functions 
 *
 * @author (c)2021 Petr Vanek, petr@fotoventus.cz
 */


 "use strict";

 /**
  * converts a string to a byte array
  * @param {string} str 
  * @returns Uint8Array
  */
mysafe.utils.ascii2Bytes =  function(str) {
    var chars = [];
    for (var i = 0; i < str.length; ++i)
        chars.push(str.charCodeAt(i));
    return new Uint8Array(chars);
}

/**
 * converts a byte array to a string
 * @param {Uint8Array} bytes 
 * @returns string
 */
mysafe.utils.bytes2Ascii = function(bytes) {
    return String.fromCharCode.apply(null, new Uint8Array(bytes));
}

/**
 * converts a byte array to a hex string
 * @param {Uint8Array} bytes 
 * @returns Hex string
 */
mysafe.utils.bytes2Hex =  function(bytes) {
    if (!bytes)
        return null;

    bytes = new Uint8Array(bytes);
    var hexBytes = [];

    for (var i = 0; i < bytes.length; ++i) {
        var byteString = bytes[i].toString(16);
        if (byteString.length < 2)
            byteString = "0" + byteString;
        hexBytes.push(byteString);
    }

    return hexBytes.join("");
}

/**
 * converts a hex string to a byte array
 * @param {string} hexString  - hexa string
 * @returns 
 */
mysafe.utils.hex2Bytes =  function(hexString) {
    if (hexString.length % 2 != 0)
            throw new mysafe.exception.invalidParam("invalid hex");

    var arrayBuffer = new Uint8Array(hexString.length / 2);

    for (var i = 0; i < hexString.length; i += 2) {
        var byteValue = parseInt(hexString.substr(i, 2), 16);
               
        if (isNaN(byteValue))
            throw new mysafe.exception.invalidParam("invalid hex");

        arrayBuffer[i / 2] = byteValue;
    }

    return arrayBuffer;
}

/**
 * converts a base64 string to a byte array
 * @param {string} base64 
 * @returns Uint8Array
 */
mysafe.utils.base642Bytes =  function (base64) {
    var bytes = new Uint8Array(0);
    try {
        var binary_string = window.atob(base64);
        var len = binary_string.length;
        bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
    }
    catch (e) {
        throw new mysafe.exception.invalidParam("invalid base64");
    }

    return new Uint8Array(bytes.buffer);
}

/**
 * converts a byte array to a base64 string
 * @param {*} bytes 
 * @returns 
 */
mysafe.utils.bytes2Base64 =  function (bytes) {
  return btoa(new Uint8Array(bytes).reduce((data,byte)=>(data.push(String.fromCharCode(byte)),data),[]).join(''));
}

/**
 * 
 * @param {string} str JS string 
 * @returns 
 */
mysafe.utils.string2Utf8 =  function(str) {

    var utf8 = [];
    for (var i=0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        if (code < 0x80) { 
            // one byte
            utf8.push(code);
        } else if (code < 0x800) {
            // two bytes
            utf8.push(0xc0 | (code >> 6), 
                      0x80 | (code & 0x3f));
        }
        else if (code < 0xd800 || code >= 0xe000) {
            utf8.push(0xe0 | (code >> 12), 
                      0x80 | ((code>>6) & 0x3f), 
                      0x80 | (code & 0x3f));
        } else {
            i++;
            // Characters outside of the base multilingual plane (BMP) are represented using a surrogate pair in UTF-16
            code = 0x10000 + (((code & 0x3ff)<<10)
                      | (str.charCodeAt(i) & 0x3ff));
            utf8.push(0xf0 | (code >>18), 
                      0x80 | ((code>>12) & 0x3f), 
                      0x80 | ((code>>6) & 0x3f), 
                      0x80 | (code & 0x3f));
        }
    }
    return new Uint8Array(utf8);;
}

/**
 * Convert bytes to UTF16 string aka JS String
 * @param {*} bytes 
 * @returns 
 */
mysafe.utils.utf82string =  function(indata) {
    const bytes = new Uint8Array(indata);
    var code1, code2, code3;
    var outString = "";
    var i = 0;
    while(i < bytes.length) {
        code1 = bytes[i++];
        switch(code1 >> 4)
        { 
        case 0: 
        case 1: 
        case 2: 
        case 3: 
        case 4: 
        case 5: 
        case 6: 
        case 7:
            outString += String.fromCharCode(code1);
            break;
        case 12: case 13:
            code2 = bytes[i++];
            outString += String.fromCharCode(((code1 & 0x1F) << 6) | (code2 & 0x3F));
            break;
        case 14:
            code2 = bytes[i++];
            code3 = bytes[i++];
            outString += String.fromCharCode(((code1 & 0x0F) << 12) | ((code2 & 0x3F) << 6) | ((code3 & 0x3F) << 0));
            break;
        }
    }

    return outString;
}

