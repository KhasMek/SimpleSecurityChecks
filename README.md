# Simple Security Checks

Android app that runs device and app security checks.

## Security Checks

### Root Detection
- **SU binary paths:** `/system/xbin/su`, `/system/bin/su`, `/sbin/su`, `/system/su`, `/system/bin/.ext/.su`, `/data/local/xbin/su`, `/data/local/bin/su`, `/data/local/su`, `/su/bin/su`
- **Root management apps:** `com.topjohnwu.magisk`, `eu.chainfire.supersu`, `com.koushikdutta.superuser`, `com.noshufou.android.su`, `com.thirdparty.superuser`, `com.yellowes.su`, `com.kingroot.kinguser`, `com.kingo.root`, `me.phh.superuser`
- **Build tags:** `test-keys` detection
- **Dangerous system properties:** `ro.debuggable=1`, `ro.secure=0`, `service.adb.root=1`, `ro.adb.secure=0`
- **RW /system mount:** checks if `/system` is mounted read-write
- **SU command execution:** attempts `su -c id`
- **Busybox binaries:** `/system/xbin/busybox`, `/system/bin/busybox`, `/sbin/busybox`, `/su/bin/busybox`, `/data/local/xbin/busybox`, `/data/local/bin/busybox`
- **Magisk artifacts:** `/sbin/.magisk`, `/cache/.disable_magisk`, `/dev/.magisk.unblock`, `/data/adb/magisk`, `/data/adb/magisk.db`, `/data/adb/modules`, magisk in PATH

### Cryptographic Operations
- **Symmetric encryption:** AES-CBC/GCM 128/256, DES, 3DES
- **Asymmetric encryption:** RSA-2048, RSA-4096
- **Hashing:** MD5, SHA-1, SHA-256, SHA-384, SHA-512
- **HMAC:** MD5, SHA1, SHA256, SHA512
- **Key derivation:** PBKDF2 with HmacSHA1/HmacSHA256
- **Digital signatures:** SHA256withRSA, SHA256withECDSA
- **Secure random:** cryptographic byte generation
- **Android Keystore:** hardware-backed AES, RSA, EC key operations

### SSL Pinning
- **OkHttp CertificatePinner:** valid pin, wrong pin rejection, backup pin fallback
- **Custom TrustManager:** strict cert validation, system-only trust store
- **HttpsURLConnection:** public key pinning verification
- **Pinning bypass detection:** proxy CAs in user trust store, Frida, Xposed, Magisk SSL modules

### Device & App Integrity
- **Emulator detection:** Build.FINGERPRINT (generic, unknown, sdk, Genymotion, nox, Andy), Build.MODEL (google_sdk, Emulator, Android SDK, sdk_gphone), Build.HARDWARE (goldfish, ranchu, vbox86), Build.PRODUCT (sdk, google_sdk, vbox86p, nox), QEMU properties (`ro.kernel.qemu`, `ro.hardware.chipname`), emulator files (`/dev/socket/qemud`, `/dev/qemu_pipe`, `/system/lib/libc_malloc_debug_qemu.so`)
- **Developer options:** USB debugging (`adb_enabled`), wireless debugging (`adb_wifi_enabled`), developer options (`development_settings_enabled`), mock locations (`allow_mock_location`, `mock_location_app`)
- **Device security:** lock screen (`KeyguardManager.isDeviceSecure`), SELinux status (`getenforce`), bootloader state (`ro.boot.flash.locked`, `ro.boot.verifiedbootstate`), verified boot state (checks for non-green state), device encryption (`ro.crypto.state`)
- **App debug status:** `ApplicationInfo.FLAG_DEBUGGABLE`, `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`, TracerPid in `/proc/self/status`
- **App installation integrity:** installer package check via `getInstallSourceInfo()`/`getInstallerPackageName()`, `ApplicationInfo.FLAG_ALLOW_BACKUP`, signing certificate SHA-256 verification, multiple signers detection via `PackageInfo.signingInfo`
- **Runtime hooking:** Frida server binary, Frida default port (27042), Frida in memory maps, Frida named threads (gmain, gdbus, gum-js-loop), Xposed framework files (XposedBridge.jar, LSPosed, EdXposed), Xposed class loaded, Xposed in stack traces, Magisk environment (`/sbin/.magisk`, `which magisk`, Magisk Manager packages), suspicious native libraries in `/proc/self/maps` (Substrate, Cydia, xhook, SandHook, Whale, ByteHook)
- **Process & environment:** active accessibility services, VPN connection (TRANSPORT_VPN), running as root (UID 0) or system (UID 1000), suspicious environment variables (`LD_PRELOAD`, `_JAVA_OPTIONS`, `CLASSPATH`)
- **Screen capture protection:** FLAG_SECURE bypass Xposed modules (`com.varuns2002.disable_flag_secure`, `fi.veekan.disableflagsecure`, `com.displaysecure`, `com.xstar97.disableflagsecure`), FLAG_SECURE bypass Magisk modules (scans `/data/adb/modules/` for flagsecure/screensecurity names), bypass classes loaded in memory, screen recording apps (`com.kimcy929.screenrecorder`, `com.hecorat.screenrecorder.free`, `com.rec.screen.recorder`, `com.rsstudio.screen.recorder`, `screenrecorder.suspended.app`), virtual/presentation displays via DisplayManager, overlay drawing permission (SYSTEM_ALERT_WINDOW)

## Build

```bash
./gradlew assembleDebug
./gradlew assembleRelease
./gradlew test
```
