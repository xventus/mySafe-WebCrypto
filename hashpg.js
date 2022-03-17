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
      const inData = document.getElementById("inputData").value;
      var binary = new Uint8Array(0);
      switch(document.getElementById("convertSelector").value) {
        case 'U':
          try {
            binary =  mysafe.utils.string2Utf8(inData);
          } catch(e) { showError("invalid UTF8?"); er = true;}
          break;
        case 'A':
          try {
            binary =  mysafe.utils.ascii2Bytes(inData);
          } catch(e) { showError("invalid ASCII?"); er = true;}
          break;
        case 'H':
          try {
            binary =  mysafe.utils.hex2Bytes(inData.replace(/\s/g,''));
          } catch(e) { showError("invalid HEX?"); er = true; }
          break;
        case 'B':
          try {
            binary =  mysafe.utils.base642Bytes(inData.replace(/\s/g,''));
          } catch(e) { showError("invalid BASE64?"); er = true; }
        break;  
  
        default:
          console.error("unknown conversion");
          er = true;
      }
  
      if (er) return;

      try {
        switch(document.getElementById("AlgSelector").value) {
            case '1':
                binary = await mysafe.hash.sha1(binary);
            break;
            case '256':
                binary =  await mysafe.hash.sha256(binary);
            break;
            case '512':
                binary =  await mysafe.hash.sha512(binary);
            break;
            default:
            console.error("invalid alg. selected");
            er = true;

        }
    } catch(e) {
        showError("compute HASH failed"); 
        binary = [];
    }

    if (er) return;  

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
  