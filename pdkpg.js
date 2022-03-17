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
      var password = new Uint8Array(0);
      switch(document.getElementById("convertSelector").value) {
        case 'U':
          try {
            password =  mysafe.utils.string2Utf8(inData);
          } catch(e) { showError("invalid data UTF8?"); er = true;}
          break;
        case 'A':
          try {
            password =  mysafe.utils.ascii2Bytes(inData);
          } catch(e) { showError("invalid data ASCII?"); er = true;}
          break;
        case 'H':
          try {
            password =  mysafe.utils.hex2Bytes(inData.replace(/\s/g,''));
          } catch(e) { showError("invalid data HEX?"); er = true; }
          break;
        case 'B':
          try {
            password =  mysafe.utils.base642Bytes(inData.replace(/\s/g,''));
          } catch(e) { showError("invalid data BASE64?");er = true; }
        break;  
  
        default:
          console.error("unknown data conversion");
          er = true;
      }

      if (er) return;

      // salt
      const insalt = document.getElementById("inputSalt").value;
      var salt = new Uint8Array(0);
      switch(document.getElementById("keyConvertSelector").value) {
        case 'U':
          try {
            salt =  mysafe.utils.string2Utf8(insalt);
          } catch(e) { showError("invalid key UTF8?"); er = true;}
          break;
        case 'A':
          try {
            salt =  mysafe.utils.ascii2Bytes(insalt);
          } catch(e) { showError("invalid key ASCII?"); er = true;}
          break;
        case 'H':
          try {
            salt =  mysafe.utils.hex2Bytes(insalt.replace(/\s/g,''));
          } catch(e) { showError("invalid key HEX?"); er = true; }
          break;
        case 'B':
          try {
            salt =  mysafe.utils.base642Bytes(insalt.replace(/\s/g,''));
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
     const cost = parseInt(document.getElementById("inputN").value);
     const blockSize =  parseInt(document.getElementById("inputR").value);
     const p =  parseInt(document.getElementById("inputP").value);
     const l =  parseInt(document.getElementById("inputL").value);
    

      try {
        binary =  await mysafe.scrypt.scryptBits( password, salt, cost,blockSize,p,l*8,alg); 
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
  