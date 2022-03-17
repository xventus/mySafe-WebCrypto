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
      var key = new Uint8Array(0);
      switch(document.getElementById("convertSelector").value) {
        case 'U':
          try {
            key =  mysafe.utils.string2Utf8(inData);
          } catch(e) { showError("invalid data UTF8?"); er = true;}
          break;
        case 'A':
          try {
            key =  mysafe.utils.ascii2Bytes(inData);
          } catch(e) { showError("invalid data ASCII?"); er = true;}
          break;
        case 'H':
          try {
            key =  mysafe.utils.hex2Bytes(inData.replace(/\s/g,''));
          } catch(e) { showError("invalid data HEX?"); er = true; }
          break;
        case 'B':
          try {
            key =  mysafe.utils.base642Bytes(inData.replace(/\s/g,''));
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
      switch(document.getElementById("saltConvertSelector").value) {
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

      // info
      const ininfo = document.getElementById("inputInfo").value;
      var info = new Uint8Array(0);
      switch(document.getElementById("infoConvertSelector").value) {
        case 'U':
          try {
            info =  mysafe.utils.string2Utf8(ininfo);
          } catch(e) { showError("invalid key UTF8?"); er = true;}
          break;
        case 'A':
          try {
            info =  mysafe.utils.ascii2Bytes(ininfo);
          } catch(e) { showError("invalid key ASCII?"); er = true;}
          break;
        case 'H':
          try {
            info =  mysafe.utils.hex2Bytes(ininfo.replace(/\s/g,''));
          } catch(e) { showError("invalid key HEX?"); er = true; }
          break;
        case 'B':
          try {
            info =  mysafe.utils.base642Bytes(ininfo.replace(/\s/g,''));
          } catch(e) { showError("invalid key BASE64?");er = true; }
        break;  
  
        default:
          console.error("unknown info conversion");
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
  
     const l =  parseInt(document.getElementById("inputL").value);
     var binary = new Uint8Array(0);
     try {
        binary =  await mysafe.hash.hkdfDerivation(key, salt, info, l*8, alg);
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
  