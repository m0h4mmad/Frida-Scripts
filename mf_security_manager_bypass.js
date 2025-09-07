Java.perform(function () {
    console.log("[*] all_check_bypass_working.js starting...");

    // ---------- Helpers ----------
    function safeJSONObject() {
        var JSONObject = Java.use('org.json.JSONObject');
        return JSONObject.$new();
    }

    function createSafeDeviceJSON() {
        var JSONObject = Java.use('org.json.JSONObject');
        var json = JSONObject.$new();
        json.put("isRooted", false);
        json.put("isEmulator", false);
        json.put("isAdbEnabled", false);
        json.put("detectedIssues", JSONObject.$new("[]"));
        return json;
    }

    function createSafeHookingJSON() {
        var JSONObject = Java.use('org.json.JSONObject');
        var json = JSONObject.$new();
        json.put("isHooked", false);
        json.put("detectedIssues", JSONObject.$new("[]"));
        return json;
    }

    function createSafeAppJSON() {
        var JSONObject = Java.use('org.json.JSONObject');
        var json = JSONObject.$new();
        json.put("isTampered", false);
        json.put("detectedIssues", JSONObject.$new("[]"));
        return json;
    }

    function createSafeSecurityCheckResult() {
        try {
            var SecurityCheckResult = Java.use("com.innov8.moneyfellowscourier.security.SecurityManager$SecurityCheckResult");
            return SecurityCheckResult.$new(
                true,  // isSecure
                true,  // runtimeIntegrity
                true,  // deviceIntegrity
                true,  // hookingFree
                true,  // debuggerFree
                true,  // appSecure
                createSafeDeviceJSON(),
                createSafeHookingJSON(),
                createSafeDeviceJSON(),
                createSafeAppJSON(),
                null
            );
        } catch (e) {
            return safeJSONObject();
        }
    }

    function createSafeSecurityStatus() {
        try {
            var SecurityStatus = Java.use("com.innov8.moneyfellowscourier.security.SecurityManager$SecurityStatus");
            return SecurityStatus.$new(true, true, createSafeSecurityCheckResult(), 1000);
        } catch (e) {
            return safeJSONObject();
        }
    }

    function createSafeIssuesMap() {
        var LinkedHashMap = Java.use("java.util.LinkedHashMap");
        var Boolean = Java.use("java.lang.Boolean");
        var map = LinkedHashMap.$new();
        var keys = [
            "isRooted","isEmulator","isDebuggerConnected","isAdbEnabled",
            "isTampered","isHooked","frida_detected","xposed_detected",
            "objection_detected","suspicious_processes","suspicious_libraries",
            "suspicious_memory_regions","app_debuggable","debug_mode","repackaging_detected"
        ];
        keys.forEach(function(k){ map.put(k, Boolean.valueOf(false)); });
        return map;
    }

    // ---------- 1) SecurityManager core ----------

    try {
        var SecurityManager = Java.use("com.innov8.moneyfellowscourier.security.SecurityManager");

        if (SecurityManager.startContinuousMonitoring) {
            SecurityManager.startContinuousMonitoring.implementation = function () {
                console.log("[+] startContinuousMonitoring() bypassed (no monitoring thread started)");
            };
            console.log("[+] Hooked SecurityManager.startContinuousMonitoring");
        }
    } catch (e) {
        console.log("[-] Could not hook SecurityManager.startContinuousMonitoring: " + e);
    }

    // Hook Companion.getInstance to patch instance methods when created
    try {
        var SMCompanion = Java.use("com.innov8.moneyfellowscourier.security.SecurityManager$Companion");
        SMCompanion.getInstance.implementation = function (ctx) {
            console.log("[*] SecurityManager.getInstance intercepted");
            var inst = this.getInstance(ctx);
            try {
                // patch instance methods safely
                try { inst.clearSensitiveDataAndShowDialog.implementation = function(m, d) { console.log("[*] clearSensitiveDataAndShowDialog blocked: " + m); }; } catch(e){}
                try { inst.showSecurityViolationDialog.implementation = function(m, d) { console.log("[*] showSecurityViolationDialog blocked: " + m); }; } catch(e){}
                try { inst.notifyThreatDetected.implementation = function(t, d) { console.log("[*] notifyThreatDetected suppressed: " + t); }; } catch(e){}
                try { inst.performSecurityCheck.implementation = function() { return createSafeSecurityCheckResult(); }; } catch(e){}
                try { inst.getSecurityStatus.implementation = function() { return createSafeSecurityStatus(); }; } catch(e){}
                try { inst.isDeviceRooted.implementation = function() { return false; }; } catch(e){}
                try { inst.isRunningOnEmulator.implementation = function() { return false; }; } catch(e){}
                try { inst.isDebuggerConnected.implementation = function() { return false; }; } catch(e){}
                try { inst.isAdbEnabled.implementation = function() { return false; }; } catch(e){}
                try { inst.checkDeviceIntegrity.implementation = function() { return createSafeDeviceJSON(); }; } catch(e){}
                try { inst.checkHookingFrameworks.implementation = function() { return createSafeHookingJSON(); }; } catch(e){}
                try { inst.checkAppIntegrity.implementation = function() { return createSafeAppJSON(); }; } catch(e){}
                try { inst.getThreatReport.implementation = function() { return createSafeSecurityCheckResult(); }; } catch(e){}
                try { inst.checkSpecificIssues.implementation = function() { return createSafeIssuesMap(); }; } catch(e){}
                console.log("[+] Patched SecurityManager instance methods");
            } catch (inner) {
                console.log("[-] Error patching SecurityManager instance: " + inner);
            }
            return inst;
        };
        console.log("[+] Hooked SecurityManager$Companion.getInstance");
    } catch (e) {
        console.log("[-] Could not hook SecurityManager$Companion.getInstance: " + e);
    }

    // ---------- 2) Component-level hooks (detectors) ----------
    try {
        var HookingFrameworkDetector = Java.use("com.innov8.moneyfellowscourier.security.HookingFrameworkDetector");
        try { HookingFrameworkDetector.quickFridaCheck.implementation = function() { return false; }; } catch(e){}
        try { HookingFrameworkDetector.check.implementation = function() { return createSafeHookingJSON(); }; } catch(e){}
        console.log("[+] HookingFrameworkDetector patched");
    } catch (e) {
        console.log("[-] HookingFrameworkDetector not present / hook error: " + e);
    }

    try {
        var DeviceIntegrityChecker = Java.use("com.innov8.moneyfellowscourier.security.DeviceIntegrityChecker");
        try { DeviceIntegrityChecker.check.implementation = function(){ return createSafeDeviceJSON(); }; } catch(e){}
        try { DeviceIntegrityChecker.checkRoot.implementation = function(){ var JSONObject = Java.use('org.json.JSONObject'); var j = JSONObject.$new(); j.put("isRooted", false); return j; }; } catch(e){}
        try { DeviceIntegrityChecker.checkEmulator.implementation = function(){ var JSONObject = Java.use('org.json.JSONObject'); var j = JSONObject.$new(); j.put("isEmulator", false); return j; }; } catch(e){}
        console.log("[+] DeviceIntegrityChecker patched");
    } catch (e) {
        console.log("[-] DeviceIntegrityChecker hook error: " + e);
    }

    try {
        var DebuggerDetector = Java.use("com.innov8.moneyfellowscourier.security.DebuggerDetector");
        try {
            DebuggerDetector.check.implementation = function() {
                var JSONObject = Java.use('org.json.JSONObject');
                var j = JSONObject.$new();
                j.put("isDebuggerAttached", false);
                j.put("detectedIssues", JSONObject.$new("[]"));
                return j;
            };
        } catch(e){}
        try { DebuggerDetector.isAdbEnabled.implementation = function(){ return false; }; } catch(e){}
        console.log("[+] DebuggerDetector patched");
    } catch (e) {
        console.log("[-] DebuggerDetector hook error: " + e);
    }

    try {
        var AppIntegrityChecker = Java.use("com.innov8.moneyfellowscourier.security.AppIntegrityChecker");
        try { AppIntegrityChecker.check.implementation = function(){ return createSafeAppJSON(); }; } catch(e){}
        console.log("[+] AppIntegrityChecker patched");
    } catch (e) {
        console.log("[-] AppIntegrityChecker hook error: " + e);
    }

    try {
        var RuntimeIntegrityMonitor = Java.use("com.innov8.moneyfellowscourier.security.RuntimeIntegrityMonitor");
        try { RuntimeIntegrityMonitor.isMonitoringActive.implementation = function(){ return true; }; } catch(e){}
        try { RuntimeIntegrityMonitor.startMonitoring.implementation = function(){ console.log("[*] RuntimeIntegrityMonitor.startMonitoring nop"); }; } catch(e){}
        try { RuntimeIntegrityMonitor.stopMonitoring.implementation = function(){ console.log("[*] RuntimeIntegrityMonitor.stopMonitoring nop"); }; } catch(e){}
        console.log("[+] RuntimeIntegrityMonitor patched");
    } catch (e) {
        console.log("[-] RuntimeIntegrityMonitor hook error: " + e);
    }

    // ---------- 3) Prevent SecurityNotificationActivity from launching ----------
    try {
        var SNAComp = Java.use("com.innov8.moneyfellowscourier.security.SecurityNotificationActivity$Companion");
        try {
            if (SNAComp.launch) {
                SNAComp.launch.implementation = function(ctx, msg, details) {
                    console.log("[+] SecurityNotificationActivity.Companion.launch blocked");
                    return;
                };
            }
        } catch(e){}
        try {
            if (SNAComp["launch$default"]) {
                SNAComp["launch$default"].implementation = function(a,b,c,d,e,f) {
                    console.log("[+] SecurityNotificationActivity.Companion.launch$default blocked");
                    return;
                };
            }
        } catch(e){}
        console.log("[+] SecurityNotificationActivity Companion hooks installed");
    } catch (e) {
        console.log("[-] Could not hook SecurityNotificationActivity$Companion: " + e);
    }

    // Intercept startActivity (Activity & ContextWrapper) to drop SecurityNotificationActivity Intents
    (function () {
        function isSecurityIntent(intent) {
            try {
                if (!intent) return false;
                var comp = intent.getComponent && intent.getComponent();
                if (comp) {
                    var cls = comp.getClassName && comp.getClassName();
                    if (cls && cls.indexOf("com.innov8.moneyfellowscourier.security.SecurityNotificationActivity") !== -1) return true;
                }
                if (intent.hasExtra && (intent.hasExtra("security_message") || intent.hasExtra("security_details"))) return true;
            } catch (e) {}
            return false;
        }

        try {
            var Activity = Java.use("android.app.Activity");
            Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
                if (isSecurityIntent(intent)) { console.log("[+] Activity.startActivity blocked SecurityNotificationActivity"); return; }
                return this.startActivity(intent);
            };
            Activity.startActivity.overload('android.content.Intent','android.os.Bundle').implementation = function(intent, b) {
                if (isSecurityIntent(intent)) { console.log("[+] Activity.startActivity(bundle) blocked SecurityNotificationActivity"); return; }
                return this.startActivity(intent, b);
            };
        } catch (e) {}

        try {
            var CW = Java.use("android.content.ContextWrapper");
            CW.startActivity.overload('android.content.Intent').implementation = function(intent) {
                if (isSecurityIntent(intent)) { console.log("[+] ContextWrapper.startActivity blocked"); return; }
                return this.startActivity(intent);
            };
            CW.startActivity.overload('android.content.Intent','android.os.Bundle').implementation = function(intent, b) {
                if (isSecurityIntent(intent)) { console.log("[+] ContextWrapper.startActivity(bundle) blocked"); return; }
                return this.startActivity(intent, b);
            };
        } catch (e) {}
    })();

    // If activity still launches, finish it immediately and avoid lambdas running
    try {
        var SNA = Java.use("com.innov8.moneyfellowscourier.security.SecurityNotificationActivity");
        SNA.onCreate.implementation = function(bundle) {
            console.log("[+] SecurityNotificationActivity.onCreate -> immediate finish");
            var Activity = Java.use("android.app.Activity");
            Activity.onCreate.call(this, bundle);
            try { this.finish(); } catch(e){}
        };
        SNA.onDestroy.implementation = function() {
            console.log("[+] SecurityNotificationActivity.onDestroy nop");
            var Activity = Java.use("android.app.Activity");
            Activity.onDestroy.call(this);
        };
        // Try neutralizing synthetic lambdas that call System.exit
        try { if (SNA["onDestroy$lambda$3"]) SNA["onDestroy$lambda$3"].implementation = function(){ console.log("[+] onDestroy$lambda$3 neutralized"); }; } catch(e){}
        try { if (SNA["finishAndExit$lambda$2"]) SNA["finishAndExit$lambda$2"].implementation = function(){ console.log("[+] finishAndExit$lambda$2 neutralized"); }; } catch(e){}
        console.log("[+] SecurityNotificationActivity lifecycle hooks installed");
    } catch (e) {
        console.log("[-] SecurityNotificationActivity lifecycle hook error: " + e);
    }

    // ---------- 4) Drop dangerous messages at Handler.dispatchMessage level ----------
    try {
        var Handler = Java.use("android.os.Handler");
        Handler.dispatchMessage.overload('android.os.Message').implementation = function(msg) {
            try {
                if (!msg) return this.dispatchMessage(msg);
                var cb = msg.getCallback && msg.getCallback();
                if (cb) {
                    var repr = "";
                    try { repr = (cb.$className ? cb.$className : cb.toString()) + ""; } catch(e){ try { repr = cb.toString() + ""; } catch(e) { repr = "";} }
                    repr = repr || "";
                    var suspicious = false;
                    try {
                        // specific names we've seen: u81, j2, or synthetic lambdas referencing SecurityNotificationActivity
                        if (repr.indexOf("u81") !== -1) suspicious = true;
                        if (repr.indexOf("j2") !== -1) suspicious = true;
                        if (repr.indexOf("SecurityNotificationActivity") !== -1) suspicious = true;
                        if (repr.indexOf("finishAndExit") !== -1) suspicious = true;
                        if (repr.indexOf("onDestroy$lambda") !== -1) suspicious = true;
                        if (repr.indexOf("lambda$") !== -1 && repr.indexOf("SecurityNotificationActivity") !== -1) suspicious = true;
                        if (repr.indexOf("frida") !== -1) suspicious = true; // defensive
                    } catch(e) {}
                    if (suspicious) {
                        console.log("[+] Dropping Message callback: " + repr);
                        return; // drop message (prevents runnable running)
                    }
                }
            } catch (e) {}
            return this.dispatchMessage(msg);
        };
        console.log("[+] Handler.dispatchMessage hook installed (drops suspicious callbacks)");
    } catch (e) {
        console.log("[-] Handler.dispatchMessage hook failed: " + e);
    }

    // also keep post/postDelayed fallback
    try {
        var Handler2 = Java.use("android.os.Handler");
        Handler2.post.overload('java.lang.Runnable').implementation = function(r) {
            try {
                var n = r.$className ? r.$className : r.toString();
                n = n || "";
                if (n.indexOf("u81") !== -1 || n.indexOf("j2") !== -1 || n.indexOf("SecurityNotificationActivity") !== -1) {
                    console.log("[+] Dropped Handler.post of: " + n);
                    return true;
                }
            } catch(e){}
            return this.post(r);
        };
        Handler2.postDelayed.overload('java.lang.Runnable','long').implementation = function(r, d) {
            try {
                var n = r.$className ? r.$className : r.toString();
                n = n || "";
                if (n.indexOf("u81") !== -1 || n.indexOf("j2") !== -1 || n.indexOf("SecurityNotificationActivity") !== -1) {
                    console.log("[+] Dropped Handler.postDelayed of: " + n + " delay=" + d);
                    return true;
                }
            } catch(e){}
            return this.postDelayed(r, d);
        };
        console.log("[+] Handler.post* fallback hooks installed");
    } catch (e) {
        console.log("[-] Handler.post* fallback hook failed: " + e);
    }

    // Try to NOP common runnables classes if they are loaded
    (function tryNopRunnable(name) {
        try {
            var C = Java.use(name);
            if (C && C.run) {
                C.run.implementation = function() { console.log("[+] " + name + ".run() nop"); return; };
                console.log("[+] NOP run() for " + name);
            }
        } catch (e) { /* ignore if class not present */ }
    })("u81");
    (function tryNopRunnable2(name) {
        try {
            var C = Java.use(name);
            if (C && C.run) {
                C.run.implementation = function() { console.log("[+] " + name + ".run() nop"); return; };
                console.log("[+] NOP run() for " + name);
            }
        } catch (e) { }
    })("j2");

    // ---------- 5) Neutralize SecurityViolationHandler and prevent exit logic ----------
    try {
        var SVHComp = Java.use("com.innov8.moneyfellowscourier.security.SecurityViolationHandler$Companion");

        try { SVHComp.exitAppSecurely.implementation = function(reason) { console.log("[+] exitAppSecurely blocked: " + reason); }; } catch(e){}
        try { SVHComp.showFallbackDialog.implementation = function(ctx, list) { console.log("[+] showFallbackDialog blocked"); }; } catch(e){}
        try { SVHComp.showNotificationAndExit.implementation = function(ctx, list) { console.log("[+] showNotificationAndExit blocked"); }; } catch(e){}
        try { SVHComp.showSecurityViolationDialog.implementation = function(ctx, list) { console.log("[+] showSecurityViolationDialog blocked"); }; } catch(e){}
        try { SVHComp.handleSecurityViolation.implementation = function(ctx, status) { console.log("[+] handleSecurityViolation blocked"); }; } catch(e){}

        console.log("[+] SecurityViolationHandler.Companion neutralized");
    } catch (e) {
        console.log("[-] Could not hook SecurityViolationHandler$Companion: " + e);
    }

    try {
        var SVH = Java.use("com.innov8.moneyfellowscourier.security.SecurityViolationHandler");
        try { SVH.onThreatDetected.implementation = function(t, d) { console.log("[+] SecurityViolationHandler.onThreatDetected blocked: " + t); }; } catch(e){}
        try { SVH.onSecurityStatusChanged.implementation = function(s) { console.log("[+] SecurityViolationHandler.onSecurityStatusChanged blocked"); }; } catch(e){}
        try { SVH.registerForRealTimeMonitoring.implementation = function(ctx) { console.log("[+] registerForRealTimeMonitoring blocked"); }; } catch(e){}
        console.log("[+] SecurityViolationHandler instance hooks installed");
    } catch (e) {
        console.log("[-] Could not hook SecurityViolationHandler class: " + e);
    }

    // ---------- 6) Bypass SecureHashStorage integrity checks ----------
    try {
        var SecureHashStorage = Java.use("com.innov8.moneyfellowscourier.security.SecureHashStorage");
        try { SecureHashStorage.verifyHash.implementation = function(ht, actual) { console.log("[+] SecureHashStorage.verifyHash forced true"); return true; }; } catch(e){}
        try { SecureHashStorage.getApkHash.implementation = function() { console.log("[+] SecureHashStorage.getApkHash forced null"); return null; }; } catch(e){}
        try { SecureHashStorage.getDexHash.implementation = function() { console.log("[+] SecureHashStorage.getDexHash forced null"); return null; }; } catch(e){}
        console.log("[+] SecureHashStorage hooks installed");
    } catch (e) {
        console.log("[-] SecureHashStorage hook error: " + e);
    }

    // ---------- 7) No-op App.initializeSecurity (if present) ----------
    try {
        var App = Java.use("com.innov8.moneyfellowscourier.app.App");
        if (App["initializeSecurity"]) {
            try { App["initializeSecurity"].implementation = function() { console.log("[+] App.initializeSecurity blocked"); }; } catch(e){}
            console.log("[+] App.initializeSecurity hooked");
        }
    } catch (e) {
        // ignore if not present
    }

    // ---------- Final log ----------
    console.log("[*] all_check_bypass_working.js loaded.");
    console.log("[*] Summary: monitoring disabled, detectors patched, SecurityViolationHandler neutralized, SecurityNotificationActivity blocked, Handler messages dropped, SecureHashStorage patched.");
});
