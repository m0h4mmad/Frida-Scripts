// MINIMALIST SAFE APPROACH - Least invasive
console.log("[+] Minimalist safe approach");

function minimalPatch() {
    var libnative = Module.findBaseAddress("libnative-lib.so");
    if (libnative) {
        try {
            var detectFunc = libnative.add(0x15d8);
            Memory.protect(detectFunc, 4, 'rwx');
            Memory.writeU32(detectFunc, 0xD65F03C0);
            console.log("[+] Minimal patch successful");
        } catch (e) {
            console.log("[-] Minimal patch failed");
        }
    } else {
        console.log("[-] libnative-lib.so not found yet");
    }
}

var attempts = 0;
var patchInterval = setInterval(function() {
    attempts++;
    minimalPatch();
    
    var libnative = Module.findBaseAddress("libnative-lib.so");
    if (libnative || attempts > 10) {
        clearInterval(patchInterval);
        if (libnative) {
            console.log("[+] Library found after " + attempts + " attempts");
        }
    }
}, 300);

console.log("lol easy");
