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


async function generateSym() {
    clearError();
    var er = false;
  
     const lenBits =  parseInt(document.getElementById("inputL").value);
     var binary = new Uint8Array(0);

    try {
        binary = await mysafe.sym.exportKeyBytes(await mysafe.sym.generateKey(lenBits));
      } catch(e) {
        showError("generate sym. key failed: " + e.message);binary = []; 
      }
       

      if (binary.length!=0) {  
        switch(document.getElementById("convertSelectorKey").value) {
            case 'H':
                document.getElementById("inputKey").value = mysafe.utils.bytes2Hex(binary);
              break;
            case 'B':
                document.getElementById("inputKey").value = mysafe.utils.bytes2Base64(binary);
              break;  
      
            default:
              console.error("unknown data conversion");
              er = true;
          }
    

      } else {
        document.getElementById("inputKey").value="";
      }
}


async function encryptSym() {
    clearError();
    var er = false;

    // encryption key
    const inKey = document.getElementById("inputKey").value;
    var key = new Uint8Array(0);
    switch(document.getElementById("convertSelectorKey").value) {
      case 'H':
        try {
            key =  mysafe.utils.hex2Bytes(inKey.replace(/\s/g,''));
        } catch(e) { showError("invalid private key  HEX?"); er = true; }
        break;
      case 'B':
        try {
            key =  mysafe.utils.base642Bytes(inKey.replace(/\s/g,''));
        } catch(e) { showError("invalid private key  BASE64?");er = true; }
      break;  

      default:
        console.error("unknown key conversion");
        er = true;
    }

    if (er) return;

    // data
    const inData = document.getElementById("inputData").value;
    var plain = new Uint8Array(0);
    switch(document.getElementById("convertSelector").value) {
      case 'U':
        try {
            plain =  mysafe.utils.string2Utf8(inData);
        } catch(e) { showError("invalid data UTF8?"); er = true;}
        break;
      case 'A':
        try {
            plain =  mysafe.utils.ascii2Bytes(inData);
        } catch(e) { showError("invalid data ASCII?"); er = true;}
        break;
      case 'H':
        try {
            plain =  mysafe.utils.hex2Bytes(inData.replace(/\s/g,''));
        } catch(e) { showError("invalid data HEX?"); er = true; }
        break;
      case 'B':
        try {
            plain =  mysafe.utils.base642Bytes(inData.replace(/\s/g,''));
        } catch(e) { showError("invalid data BASE64?");er = true; }
      break;  

      default:
        console.error("unknown plain conversion");
        er = true;
    }

    if (er) return;

    try {
        const encK = await mysafe.sym.getKeyFromBytes(key,'AES-GCM');
        binary =  await mysafe.enc.encryptData(encK, plain, 12,'AES-GCM');
       
        switch(document.getElementById("convertSelector2").value) {
            case 'H':
                document.getElementById("inputEData").innerText = mysafe.utils.bytes2Hex(binary); 
              break;
            case 'B':
                document.getElementById("inputEData").innerText = mysafe.utils.bytes2Base64(binary); 
            break;  
      
            default:
              console.error("unknown data conversion");
              er = true;
        }    

      } catch(e) {
        showError("encryption failed: " + e.message); 
      }
       

      if (binary.length==0) {  
        document.getElementById("inputEData").innerText = "";
      } 
}

async function decryptSym() {
    clearError();
    var er = false;

    // encryption key
    const inKey = document.getElementById("inputKey").value;
    var key = new Uint8Array(0);
    switch(document.getElementById("convertSelectorKey").value) {
      case 'H':
        try {
            key =  mysafe.utils.hex2Bytes(inKey.replace(/\s/g,''));
        } catch(e) { showError("invalid private key  HEX?"); er = true; }
        break;
      case 'B':
        try {
            key =  mysafe.utils.base642Bytes(inKey.replace(/\s/g,''));
        } catch(e) { showError("invalid private key  BASE64?");er = true; }
      break;  

      default:
        console.error("unknown key conversion");
        er = true;
    }

    if (er) return;

    // encdata
    const inData = document.getElementById("inputEData").value;
    var encdata = new Uint8Array(0);
    switch(document.getElementById("convertSelector2").value) {
      case 'H':
        try {
            encdata =  mysafe.utils.hex2Bytes(inData.replace(/\s/g,''));
        } catch(e) { showError("invalid enc data HEX?"); er = true; }
        break;
      case 'B':
        try {
            encdata =  mysafe.utils.base642Bytes(inData.replace(/\s/g,''));
        } catch(e) { showError("invalid enc data BASE64?");er = true; }
      break;  

      default:
        console.error("unknown enc conversion");
        er = true;
    }

    if (er) return;
    var binary = new Uint8Array(0);
    try {
        const encK = await mysafe.sym.getKeyFromBytes(key,'AES-GCM');
        binary =  await mysafe.enc.decryptData(encK, encdata, 12,'AES-GCM');
       
        switch(document.getElementById("convertSelector").value) {
            case 'A':
                document.getElementById("inputData").value = mysafe.utils.bytes2Ascii(binary); 
              break;
            case 'U':
                document.getElementById("inputData").value = mysafe.utils.utf82string(binary); 
              break;
            case 'H':
                document.getElementById("inputData").value = mysafe.utils.bytes2Hex(binary); 
              break;
            case 'B':
                document.getElementById("inputData").value = mysafe.utils.bytes2Base64(binary); 
            break;  
      
            default:
              console.error("unknown data conversion");
              er = true;
        }    

      } catch(e) {
        showError("encryption failed: " + e.message); 
      }
       

      if (binary.length==0) {  
        document.getElementById("inputEData").value = "";
      } 

}

function encrypt() {
    encryptSym();
}

function decrypt() {
    decryptSym();
}

function generate() {
    generateSym();
}