package com.oblador.keychain;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;

public class DeviceAvailability {
    public static boolean isFingerprintAuthAvailable(Context context) {
        if (android.os.Build.VERSION.SDK_INT >= 23) {
            FingerprintManager fingerprintManager =
                    (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
            return fingerprintManager != null &&
                    context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED &&
                    fingerprintManager.isHardwareDetected() &&
                    fingerprintManager.hasEnrolledFingerprints();
        }
        return false;
    }

    public static boolean isDeviceSecure(Context context) {
        KeyguardManager keyguardManager =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return Build.VERSION.SDK_INT >= 23 && keyguardManager != null && keyguardManager.isDeviceSecure();
    }
}
