Java.perform(function() {
    // Use the intent class
    var IntentClass = Java.use("android.content.Intent");
    // override implementation
    IntentClass.getStringExtra.overload('java.lang.String').implementation = function(str) {
        let extra = this.getStringExtra(str);
        let action = this.getAction();
        if (action == "TALSEC_INFO") {
            console.log(`\n[+] Hooking getStringExtra("${str}") from ${action}`);
            console.log(`\t Bypassing ${extra} detection`); 
            
            // empty extra 
            extra = "";
        }
        return extra;
    };
});
