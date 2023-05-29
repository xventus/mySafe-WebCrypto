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
    const inData = document.getElementById("inputData").value;
    var binary = new Uint8Array(0);
    switch(document.getElementById("convertSelector").value) {
      case 'U':
        try {
          binary =  mysafe.utils.string2Utf8(inData);
        } catch(e) { showError("invalid UTF8?"); }
        break;
      case 'A':
        try {
          binary =  mysafe.utils.ascii2Bytes(inData);
        } catch(e) { showError("invalid ASCII?"); }
        break;
      case 'H':
        try {
          binary =  mysafe.utils.hex2Bytes(inData.replace(/\s/g,''));
        } catch(e) { showError("invalid HEX?"); }
        break;
      case 'B':
        try {
          binary =  mysafe.utils.base642Bytes(inData.replace(/\s/g,''));
        } catch(e) { showError("invalid BASE64?"); }
      break;  

      default:
        console.error("unknown conversion");
    }
    
    if (binary.length!=0) {  
      document.getElementById("HexOutput").innerText = mysafe.utils.bytes2Hex(binary);
      document.getElementById("HexOutput2").innerText = mysafe.utils.bytes2HexSep(binary);
      document.getElementById("B64Output").innerText = mysafe.utils.bytes2Base64(binary);
      document.getElementById("AsciiOutput").innerText = mysafe.utils.bytes2Ascii(binary); 
      document.getElementById("UTFOutput").innerText = mysafe.utils.utf82string(binary); 
    } else {
      document.getElementById("HexOutput").innerText ="";
      document.getElementById("HexOutput2").innerText ="";
      document.getElementById("B64Output").innerText ="";
      document.getElementById("AsciiOutput").innerText ="";
      document.getElementById("UTFOutput").innerText = "";
    }
}

function conversion() {
    conversionAsync();
}
