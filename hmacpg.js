/** @fileOverview  demonstration how to use mysafe JS  
 *
 * @author (c)2022 Petr Vanek, petr@fotoventus.cz
 */

function showError(msg) {
    document.getElementById("conversionAlert").className = "alert alert-danger";
    document.getElementById("conversionAlert").innerText = msg;
  }
  
  function clearError() {
    document.getElementById("conversionAlert").className = "hidden";
    document.getElementById("conversionAlert").innerText = '';
  }

  function checkMySafe() {
    if (!mysafe.isReady())  showError("WebCrypto API not supported");
 }

  
  async function  conversionAsync() {
      clearError();
      var er = false;
      // data
      const inData = document.getElementById("inputData").value;
      var data = new Uint8Array(0);
      switch(document.getElementById("convertSelector").value) {
        case 'U':
          try {
            data =  mysafe.utils.string2Utf8(inData);
          } catch(e) { showError("invalid data UTF8?"); er = true;}
          break;
        case 'A':
          try {
            data =  mysafe.utils.ascii2Bytes(inData);
          } catch(e) { showError("invalid data ASCII?"); er = true;}
          break;
        case 'H':
          try {
            data =  mysafe.utils.hex2Bytes(inData.replace(/\s/g,''));
          } catch(e) { showError("invalid data HEX?"); er = true; }
          break;
        case 'B':
          try {
            data =  mysafe.utils.base642Bytes(inData.replace(/\s/g,''));
          } catch(e) { showError("invalid data BASE64?");er = true; }
        break;  
  
        default:
          console.error("unknown data conversion");
          er = true;
      }

      if (er) return;

      // key
      const inKey = document.getElementById("inputKey").value;
      var binaryKey = new Uint8Array(0);
      switch(document.getElementById("keyConvertSelector").value) {
        case 'U':
          try {
            binaryKey =  mysafe.utils.string2Utf8(inKey);
          } catch(e) { showError("invalid key UTF8?"); er = true;}
          break;
        case 'A':
          try {
            binaryKey =  mysafe.utils.ascii2Bytes(inKey);
          } catch(e) { showError("invalid key ASCII?"); er = true;}
          break;
        case 'H':
          try {
            binaryKey =  mysafe.utils.hex2Bytes(inKey.replace(/\s/g,''));
          } catch(e) { showError("invalid key HEX?"); er = true; }
          break;
        case 'B':
          try {
            binaryKey =  mysafe.utils.base642Bytes(inKey.replace(/\s/g,''));
          } catch(e) { showError("invalid key BASE64?");er = true; }
        break;  
  
        default:
          console.error("unknown key conversion");
          er = true;
      }
      
      if (er) return;

      // alg
      var alg = 'SHA-1';  
     switch(document.getElementById("AlgSelector").value) {
        case '1':
            alg = 'SHA-1';
        break;
        case '256':
            alg = 'SHA-256';
        break;
        case '512':
            alg = 'SHA-512';
        break;
        default:
        console.error("invalid alg. selected");
        er = true;
     }

     if (er) return;

      try {
        binary = await mysafe.hash.hmac(binaryKey, data, alg);
      } catch(e) {
        showError("compute HMAC failed: " + e.message);binary = []; 
      }
       

      if (binary.length!=0) {  
        document.getElementById("HexOutput").innerText = mysafe.utils.bytes2Hex(binary);
        document.getElementById("B64Output").innerText = mysafe.utils.bytes2Base64(binary);
      } else {
        document.getElementById("HexOutput").innerText ="";
        document.getElementById("B64Output").innerText ="";
      }
  }
  
  function conversion() {
      conversionAsync();
  }
  