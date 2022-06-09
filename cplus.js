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

function addSlashes( str ) {
  return (str + '').replace(/[\\"]/g, '\\$&').replace(/['\n']/g,'\\n').replace(/['\r']/g,'\\r');
}

function addVariable( str ) {
  var rc = 'const std::string variable = "'
  rc = rc + str;
  rc = rc + '";'
  return rc;
}

async function  conversionAsync() {
    clearError();
    const inData = document.getElementById("inputData").value;
    var binary = new Uint8Array(0);
    var esc = addSlashes(inData);
    try {
          binary =  mysafe.utils.string2Utf8(inData);
    } catch(e) { showError("invalid data?"); }
   
    
    if (binary.length!=0) {  
      document.getElementById("EscOutput").innerText = addVariable(esc);
      document.getElementById("HexOutput").innerText = addVariable(mysafe.utils.bytes2Hex(binary));
      document.getElementById("B64Output").innerText = addVariable(mysafe.utils.bytes2Base64(binary));

    } else {
      document.getElementById("EscOutput").innerText ="";
      document.getElementById("HexOutput").innerText ="";
      document.getElementById("B64Output").innerText ="";
    }
}

function conversion() {
    conversionAsync();
}
