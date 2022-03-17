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
      
      // private key
      const inPriv = document.getElementById("inputDataPriv").value;
      var priv = new Uint8Array(0);
      switch(document.getElementById("convertSelector").value) {
        case 'H':
          try {
            priv =  mysafe.utils.hex2Bytes(inPriv.replace(/\s/g,''));
          } catch(e) { showError("invalid private key  HEX?"); er = true; }
          break;
        case 'B':
          try {
            priv =  mysafe.utils.base642Bytes(inPriv.replace(/\s/g,''));
          } catch(e) { showError("invalid private key  BASE64?");er = true; }
        break;  
  
        default:
          console.error("unknown data conversion");
          er = true;
      }

      if (er) return;

      // public key
      const inPub = document.getElementById("inputDataPub").value;
      var pub = new Uint8Array(0);
      switch(document.getElementById("convertSelector").value) {
        case 'H':
          try {
            pub =  mysafe.utils.hex2Bytes(inPub.replace(/\s/g,''));
          } catch(e) { showError("invalid private key  HEX?"); er = true; }
          break;
        case 'B':
          try {
            pub =  mysafe.utils.base642Bytes(inPub.replace(/\s/g,''));
          } catch(e) { showError("invalid private key  BASE64?");er = true; }
        break;  
  
        default:
          console.error("unknown data conversion");
          er = true;
      }

     if (er) return;

     // curve
     var curve = 'P-521';  
     switch(document.getElementById("AlgSelector").value) {
        case '256':
            curve = 'P-256';
        break;
        case '384':
            curve = 'P-384';
        break;
        case '521':
            curve = 'P-521';
        break;
        default:
        console.error("invalid curve selected");
        er = true;
     }

     if (er) return;
  
     const ecdhBits =  parseInt(document.getElementById("inputL").value);
     var binary = new Uint8Array(0);
     try {
        const privateKey = await mysafe.asym.importPrivateFromBytesECDH(priv,curve) ;
        const publicKey = await mysafe.asym.importPublicFromBytesECDH(pub,curve);
        binary =  await mysafe.sym.ecdhDerivation(privateKey, publicKey, ecdhBits);
      } catch(e) {
        showError("compute ECDH failed: " + e.message);binary = []; 
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
  


async function generateAsym() {
    clearError();
    var er = false;

     // curve
     var curve = 'P-521';  
     switch(document.getElementById("AlgSelector").value) {
        case '256':
            curve = 'P-256';
        break;
        case '384':
            curve = 'P-384';
        break;
        case '521':
            curve = 'P-521';
        break;
        default:
        console.error("invalid curve selected");
        er = true;
     }

     if (er) return;
  
     const ecdhBits =  parseInt(document.getElementById("inputL").value);
     var binary = new Uint8Array(0);
     var privB = new Uint8Array(0);
     var pubB = new Uint8Array(0);

    try {
        const keyPir = await mysafe.asym.generateECDSA(curve);
        
        privB = await mysafe.asym.exportPrivateKey2Bytes(keyPir.privateKey);
        pubB = await mysafe.asym.exportPublicKey2Bytes(keyPir.publicKey);
        
        const privateKey = await  mysafe.asym.privateDSA2ECD(keyPir.privateKey,curve) ;
        const publicKey = await mysafe.asym.publicDSA2ECD(keyPir.publicKey,curve);
        binary =  await mysafe.sym.ecdhDerivation(privateKey, publicKey, ecdhBits, );
      } catch(e) {
        showError("generate ECC failed: " + e.message);binary = []; 
      }
       

      if (binary.length!=0) {  
        document.getElementById("HexOutput").innerText = mysafe.utils.bytes2Hex(binary);
        document.getElementById("B64Output").innerText = mysafe.utils.bytes2Base64(binary);

        switch(document.getElementById("convertSelector").value) {
            case 'H':
                document.getElementById("inputDataPriv").innerText = mysafe.utils.bytes2Hex(privB); 
                document.getElementById("inputDataPub").innerText = mysafe.utils.bytes2Hex(pubB); 
              break;
            case 'B':
                document.getElementById("inputDataPriv").innerText = mysafe.utils.bytes2Base64(privB); 
                document.getElementById("inputDataPub").innerText = mysafe.utils.bytes2Base64(pubB); 
            break;  
      
            default:
              console.error("unknown data conversion");
              er = true;
        }    

      } else {
        document.getElementById("HexOutput").innerText ="";
        document.getElementById("B64Output").innerText ="";
      }
}

function generate() {
    generateAsym();
}