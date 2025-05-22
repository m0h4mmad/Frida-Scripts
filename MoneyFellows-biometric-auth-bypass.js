console.log("Fingerprint hooks loaded!");

Java.perform(function () {
    try { hookBiometricPrompt_authenticate(); }
    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }

    try { hookBiometricPrompt_authenticate2(); }
    catch (error) { console.log("hookBiometricPrompt_authenticate2 not supported on this android version") }

    try { hookFingerprintManagerCompat_authenticate(); }
    catch (error) { console.log("hookFingerprintManagerCompat_authenticate failed"); }

    try { hookFingerprintManager_authenticate(); }
    catch (error) { console.log("hookFingerprintManager_authenticate failed"); }
});

function hookBiometricPrompt_authenticate2() {
    var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
    var CryptoObject = Java.use("android.hardware.biometrics.BiometricPrompt$CryptoObject");
    var Cipher = Java.use("javax.crypto.Cipher");
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    var AuthenticationResult = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationResult");

    console.log("Hooking BiometricPrompt.authenticate2()...");

    BiometricPrompt.authenticate.overload(
        'android.hardware.biometrics.BiometricPrompt$CryptoObject',
        'android.os.CancellationSignal',
        'java.util.concurrent.Executor',
        'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
    ).implementation = function (crypto, cancel, executor, callback) {
        console.log("Bypassing BiometricPrompt.authenticate2");

        // Create a dummy valid Cipher to avoid null pointer crash
        var keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        var secretKey = keyGen.generateKey();
        var cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(1, secretKey); // ENCRYPT_MODE = 1

        var fakeCrypto = CryptoObject.$new(cipher);
        var fakeResult = AuthenticationResult.$new(fakeCrypto, 0);  // Second argument is a dummy int (e.g. userId)

        callback.onAuthenticationSucceeded(fakeResult);
    }
}

function hookBiometricPrompt_authenticate() {
    var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
    var CryptoObject = Java.use("android.hardware.biometrics.BiometricPrompt$CryptoObject");
    var Cipher = Java.use("javax.crypto.Cipher");
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    var AuthenticationResult = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationResult");

    console.log("Hooking BiometricPrompt.authenticate()...");

    BiometricPrompt.authenticate.overload(
        'android.os.CancellationSignal',
        'java.util.concurrent.Executor',
        'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
    ).implementation = function (cancel, executor, callback) {
        console.log("Bypassing BiometricPrompt.authenticate");

        // Generate dummy Cipher
        var keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        var secretKey = keyGen.generateKey();
        var cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(1, secretKey);

        var fakeCrypto = CryptoObject.$new(cipher);
        var fakeResult = AuthenticationResult.$new(fakeCrypto, 0);  // Provide second required int parameter

        callback.onAuthenticationSucceeded(fakeResult);
    }
}
