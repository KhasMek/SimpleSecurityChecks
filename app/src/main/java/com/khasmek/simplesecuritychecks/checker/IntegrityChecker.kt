package com.khasmek.simplesecuritychecks.checker

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.view.Display
import com.khasmek.simplesecuritychecks.model.CheckCategory
import com.khasmek.simplesecuritychecks.model.CheckItem
import com.khasmek.simplesecuritychecks.model.CheckResult
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

private data class IntegrityOutcome(val result: CheckResult, val detail: String)

object IntegrityChecker {

    fun getDefaultCategories(): List<CheckCategory> = listOf(
        CheckCategory(
            id = "emulator_detection",
            name = "Emulator Detection",
            description = "Detect emulator environments via build properties and artifacts",
            items = listOf(
                CheckItem("Build.FINGERPRINT contains generic/emulator"),
                CheckItem("Build.MODEL is emulator"),
                CheckItem("Build.HARDWARE is goldfish/ranchu"),
                CheckItem("Build.PRODUCT is sdk/emulator"),
                CheckItem("QEMU properties detected"),
                CheckItem("Emulator files present"),
            )
        ),
        CheckCategory(
            id = "developer_options",
            name = "Developer Options & USB Debug",
            description = "Check for developer settings that weaken security",
            items = listOf(
                CheckItem("USB debugging enabled"),
                CheckItem("Wireless debugging enabled"),
                CheckItem("Developer options enabled"),
                CheckItem("Mock locations allowed"),
            )
        ),
        CheckCategory(
            id = "device_security",
            name = "Device Security",
            description = "Verify device-level security configuration",
            items = listOf(
                CheckItem("No lock screen set"),
                CheckItem("SELinux not enforcing"),
                CheckItem("Bootloader unlocked"),
                CheckItem("Verified boot state abnormal"),
                CheckItem("Device not encrypted"),
            )
        ),
        CheckCategory(
            id = "app_debuggability",
            name = "App Debug Status",
            description = "Detect debuggable builds and attached debuggers",
            items = listOf(
                CheckItem("Debuggable flag set"),
                CheckItem("Debugger currently attached"),
                CheckItem("Waiting for debugger"),
                CheckItem("TracerPid non-zero"),
            )
        ),
        CheckCategory(
            id = "app_installation",
            name = "App Installation Integrity",
            description = "Verify app installation source and signing integrity",
            items = listOf(
                CheckItem("Not installed from Play Store"),
                CheckItem("App allows backup"),
                CheckItem("Signature mismatch"),
                CheckItem("Multiple signers detected"),
            )
        ),
        CheckCategory(
            id = "hooking_detection",
            name = "Runtime Hooking Detection",
            description = "Detect Frida, Xposed, Magisk, and other hooking frameworks",
            items = listOf(
                CheckItem("Frida server binary"),
                CheckItem("Frida default port open"),
                CheckItem("Frida in memory maps"),
                CheckItem("Frida named threads"),
                CheckItem("Xposed framework files"),
                CheckItem("Xposed class loaded"),
                CheckItem("Xposed in stack traces"),
                CheckItem("Magisk environment detected"),
                CheckItem("Suspicious native libraries"),
            )
        ),
        CheckCategory(
            id = "process_environment",
            name = "Process & Environment",
            description = "Check for suspicious runtime environment conditions",
            items = listOf(
                CheckItem("Accessibility services active"),
                CheckItem("VPN connection active"),
                CheckItem("HTTP proxy configured"),
                CheckItem("Running as root/system UID"),
                CheckItem("Suspicious environment variables"),
            )
        ),
        CheckCategory(
            id = "hardware_security",
            name = "Hardware Security",
            description = "Key attestation and hardware-backed security features",
            items = listOf(
                CheckItem("Key attestation supported"),
                CheckItem("Attestation backed by hardware"),
                CheckItem("Google attestation root certificate"),
                CheckItem("StrongBox keystore available"),
                CheckItem("Biometric hardware present"),
            )
        ),
        CheckCategory(
            id = "screen_capture_protection",
            name = "Screen Capture Protection",
            description = "Detect FLAG_SECURE bypass tools and screen capture threats",
            items = listOf(
                CheckItem("FLAG_SECURE bypass modules (Xposed)"),
                CheckItem("FLAG_SECURE bypass modules (Magisk)"),
                CheckItem("Bypass classes loaded"),
                CheckItem("Screen recording apps installed"),
                CheckItem("Virtual displays active"),
                CheckItem("Overlay drawing permitted"),
            )
        ),
    )

    fun runChecks(categories: List<CheckCategory>, context: Context): List<CheckCategory> {
        return categories.map { category ->
            val checkedItems = category.items.map { item ->
                if (!item.enabled) {
                    item.copy(result = null, detail = null)
                } else {
                    val outcome = runSingleCheck(category.id, item.label, context)
                    item.copy(result = outcome.result, detail = outcome.detail)
                }
            }
            category.copy(items = checkedItems)
        }
    }

    private fun runSingleCheck(categoryId: String, label: String, context: Context): IntegrityOutcome {
        return try {
            when (categoryId) {
                "emulator_detection" -> runEmulatorCheck(label)
                "developer_options" -> runDeveloperOptionsCheck(label, context)
                "device_security" -> runDeviceSecurityCheck(label, context)
                "app_debuggability" -> runAppDebugCheck(label, context)
                "app_installation" -> runAppInstallationCheck(label, context)
                "hooking_detection" -> runHookingDetectionCheck(label)
                "process_environment" -> runProcessEnvironmentCheck(label, context)
                "hardware_security" -> runHardwareSecurityCheck(label, context)
                "screen_capture_protection" -> runScreenCaptureProtectionCheck(label, context)
                else -> IntegrityOutcome(CheckResult.ERROR, "Unknown category")
            }
        } catch (e: Exception) {
            IntegrityOutcome(CheckResult.ERROR, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    // ── Emulator Detection ──

    private fun runEmulatorCheck(label: String): IntegrityOutcome {
        return when (label) {
            "Build.FINGERPRINT contains generic/emulator" -> {
                val fp = Build.FINGERPRINT.lowercase()
                val markers = listOf("generic", "unknown", "sdk", "genymotion", "nox", "andy")
                val found = markers.filter { fp.contains(it) }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "FINGERPRINT='${Build.FINGERPRINT}', matched: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "FINGERPRINT='${Build.FINGERPRINT}'")
                }
            }
            "Build.MODEL is emulator" -> {
                val model = Build.MODEL.lowercase()
                val markers = listOf("google_sdk", "emulator", "android sdk", "sdk_gphone")
                val found = markers.filter { model.contains(it) }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "MODEL='${Build.MODEL}', matched: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "MODEL='${Build.MODEL}'")
                }
            }
            "Build.HARDWARE is goldfish/ranchu" -> {
                val hw = Build.HARDWARE.lowercase()
                val markers = listOf("goldfish", "ranchu", "vbox86")
                val found = markers.filter { hw.contains(it) }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "HARDWARE='${Build.HARDWARE}', matched: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "HARDWARE='${Build.HARDWARE}'")
                }
            }
            "Build.PRODUCT is sdk/emulator" -> {
                val product = Build.PRODUCT.lowercase()
                val markers = listOf("sdk", "google_sdk", "vbox86p", "nox")
                val found = markers.filter { product.contains(it) }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "PRODUCT='${Build.PRODUCT}', matched: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "PRODUCT='${Build.PRODUCT}'")
                }
            }
            "QEMU properties detected" -> {
                val evidence = mutableListOf<String>()
                val propsToCheck = listOf("ro.kernel.qemu" to "1", "ro.hardware.chipname" to "goldfish")
                for ((prop, expected) in propsToCheck) {
                    val value = getSystemProperty(prop)
                    if (value.isNotEmpty()) {
                        if (expected.isEmpty() || value == expected) {
                            evidence.add("$prop=$value")
                        }
                    }
                }
                if (evidence.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No QEMU properties found")
                }
            }
            "Emulator files present" -> {
                val paths = listOf(
                    "/dev/socket/qemud",
                    "/dev/qemu_pipe",
                    "/system/lib/libc_malloc_debug_qemu.so"
                )
                val found = paths.filter { File(it).exists() }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Found: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "None of ${paths.size} emulator files found")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── Developer Options ──

    private fun runDeveloperOptionsCheck(label: String, context: Context): IntegrityOutcome {
        return when (label) {
            "USB debugging enabled" -> {
                val value = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0)
                if (value == 1) {
                    IntegrityOutcome(CheckResult.DETECTED, "adb_enabled=1")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "adb_enabled=0")
                }
            }
            "Wireless debugging enabled" -> {
                val value = try {
                    Settings.Global.getInt(context.contentResolver, "adb_wifi_enabled")
                } catch (_: Settings.SettingNotFoundException) {
                    0
                }
                if (value == 1) {
                    IntegrityOutcome(CheckResult.DETECTED, "adb_wifi_enabled=1")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "adb_wifi_enabled=0")
                }
            }
            "Developer options enabled" -> {
                val value = Settings.Global.getInt(
                    context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
                )
                if (value == 1) {
                    IntegrityOutcome(CheckResult.DETECTED, "development_settings_enabled=1")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "development_settings_enabled=0")
                }
            }
            "Mock locations allowed" -> {
                @Suppress("DEPRECATION")
                val legacyMock = Settings.Secure.getInt(
                    context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION, 0
                )
                val mockApp = Settings.Secure.getString(
                    context.contentResolver, "mock_location_app"
                )
                if (legacyMock == 1 || !mockApp.isNullOrEmpty()) {
                    val detail = buildString {
                        if (legacyMock == 1) append("allow_mock_location=1")
                        if (!mockApp.isNullOrEmpty()) {
                            if (isNotEmpty()) append("; ")
                            append("mock_location_app=$mockApp")
                        }
                    }
                    IntegrityOutcome(CheckResult.DETECTED, detail)
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No mock location settings enabled")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── Device Security ──

    private fun runDeviceSecurityCheck(label: String, context: Context): IntegrityOutcome {
        return when (label) {
            "No lock screen set" -> {
                val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                if (!km.isDeviceSecure) {
                    IntegrityOutcome(CheckResult.DETECTED, "KeyguardManager.isDeviceSecure=false")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Device has secure lock screen")
                }
            }
            "SELinux not enforcing" -> {
                try {
                    val process = Runtime.getRuntime().exec(arrayOf("getenforce"))
                    val reader = BufferedReader(InputStreamReader(process.inputStream))
                    val output = reader.readText().trim()
                    reader.close()
                    process.waitFor()
                    if (output.equals("Enforcing", ignoreCase = true)) {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "SELinux: $output")
                    } else {
                        IntegrityOutcome(CheckResult.DETECTED, "SELinux: $output")
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.ERROR, "Could not run getenforce: ${e.message}")
                }
            }
            "Bootloader unlocked" -> {
                val flashLocked = getSystemProperty("ro.boot.flash.locked")
                val verifiedBoot = getSystemProperty("ro.boot.verifiedbootstate")
                val evidence = mutableListOf<String>()
                if (flashLocked == "0") evidence.add("ro.boot.flash.locked=0")
                if (verifiedBoot == "orange") evidence.add("ro.boot.verifiedbootstate=orange")
                if (evidence.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    val detail = buildString {
                        append("flash.locked=${flashLocked.ifEmpty { "N/A" }}")
                        append(", verifiedbootstate=${verifiedBoot.ifEmpty { "N/A" }}")
                    }
                    IntegrityOutcome(CheckResult.NOT_DETECTED, detail)
                }
            }
            "Verified boot state abnormal" -> {
                val state = getSystemProperty("ro.boot.verifiedbootstate")
                if (state.isEmpty()) {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Property not available")
                } else if (state != "green") {
                    IntegrityOutcome(CheckResult.DETECTED, "ro.boot.verifiedbootstate=$state (expected 'green')")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "ro.boot.verifiedbootstate=green")
                }
            }
            "Device not encrypted" -> {
                val cryptoState = getSystemProperty("ro.crypto.state")
                if (cryptoState.isEmpty()) {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Property not available (likely encrypted by default)")
                } else if (cryptoState != "encrypted") {
                    IntegrityOutcome(CheckResult.DETECTED, "ro.crypto.state=$cryptoState")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "ro.crypto.state=encrypted")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── App Debug Status ──

    private fun runAppDebugCheck(label: String, context: Context): IntegrityOutcome {
        return when (label) {
            "Debuggable flag set" -> {
                val flags = context.applicationInfo.flags
                val debuggable = (flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
                if (debuggable) {
                    IntegrityOutcome(CheckResult.DETECTED, "ApplicationInfo.FLAG_DEBUGGABLE is set")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "FLAG_DEBUGGABLE not set")
                }
            }
            "Debugger currently attached" -> {
                if (Debug.isDebuggerConnected()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Debug.isDebuggerConnected()=true")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No debugger attached")
                }
            }
            "Waiting for debugger" -> {
                if (Debug.waitingForDebugger()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Debug.waitingForDebugger()=true")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Not waiting for debugger")
                }
            }
            "TracerPid non-zero" -> {
                try {
                    val statusFile = File("/proc/self/status")
                    val tracerLine = statusFile.readLines().find { it.startsWith("TracerPid:") }
                    val tracerPid = tracerLine?.split(":")?.getOrNull(1)?.trim() ?: "0"
                    if (tracerPid != "0") {
                        IntegrityOutcome(CheckResult.DETECTED, "TracerPid=$tracerPid (being traced)")
                    } else {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "TracerPid=0")
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.ERROR, "Cannot read /proc/self/status: ${e.message}")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── App Installation Integrity ──

    @Suppress("DEPRECATION")
    private fun runAppInstallationCheck(label: String, context: Context): IntegrityOutcome {
        val pm = context.packageManager
        val packageName = context.packageName
        return when (label) {
            "Not installed from Play Store" -> {
                val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    try {
                        pm.getInstallSourceInfo(packageName).installingPackageName
                    } catch (_: Exception) {
                        null
                    }
                } else {
                    pm.getInstallerPackageName(packageName)
                }
                val playStorePackages = listOf("com.android.vending", "com.google.android.feedback")
                if (installer == null || installer !in playStorePackages) {
                    IntegrityOutcome(CheckResult.DETECTED, "Installer: ${installer ?: "null"} (not Play Store)")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Installer: $installer")
                }
            }
            "App allows backup" -> {
                val flags = context.applicationInfo.flags
                val allowBackup = (flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) != 0
                if (allowBackup) {
                    IntegrityOutcome(CheckResult.DETECTED, "ApplicationInfo.FLAG_ALLOW_BACKUP is set")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "FLAG_ALLOW_BACKUP not set")
                }
            }
            "Signature mismatch" -> {
                try {
                    val signingInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        val pkgInfo = pm.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                        pkgInfo.signingInfo
                    } else {
                        null
                    }
                    if (signingInfo != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        val certs = if (signingInfo.hasMultipleSigners()) {
                            signingInfo.apkContentsSigners
                        } else {
                            signingInfo.signingCertificateHistory
                        }
                        if (certs != null && certs.isNotEmpty()) {
                            val digest = MessageDigest.getInstance("SHA-256")
                            val hash = digest.digest(certs[0].toByteArray())
                            val hexHash = hash.joinToString("") { "%02x".format(it) }
                            // Placeholder: in a release build, replace with your expected signing cert hash
                            val expectedHash = "PLACEHOLDER_EXPECTED_SIGNING_CERT_SHA256"
                            if (expectedHash == "PLACEHOLDER_EXPECTED_SIGNING_CERT_SHA256") {
                                IntegrityOutcome(CheckResult.NOT_DETECTED, "Cert SHA-256: $hexHash (no expected hash configured)")
                            } else if (hexHash != expectedHash) {
                                IntegrityOutcome(CheckResult.DETECTED, "Cert SHA-256: $hexHash (expected: $expectedHash)")
                            } else {
                                IntegrityOutcome(CheckResult.NOT_DETECTED, "Cert SHA-256 matches expected")
                            }
                        } else {
                            IntegrityOutcome(CheckResult.ERROR, "No signing certificates found")
                        }
                    } else {
                        val pkgInfo = pm.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNATURES)
                        val sigs = pkgInfo.signatures
                        if (sigs != null && sigs.isNotEmpty()) {
                            val digest = MessageDigest.getInstance("SHA-256")
                            val hash = digest.digest(sigs[0].toByteArray())
                            val hexHash = hash.joinToString("") { "%02x".format(it) }
                            IntegrityOutcome(CheckResult.NOT_DETECTED, "Cert SHA-256: $hexHash (no expected hash configured)")
                        } else {
                            IntegrityOutcome(CheckResult.ERROR, "No signatures found")
                        }
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.ERROR, "${e.javaClass.simpleName}: ${e.message}")
                }
            }
            "Multiple signers detected" -> {
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        val pkgInfo = pm.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                        val signingInfo = pkgInfo.signingInfo
                        if (signingInfo != null && signingInfo.hasMultipleSigners()) {
                            val count = signingInfo.apkContentsSigners.size
                            IntegrityOutcome(CheckResult.DETECTED, "$count signers detected")
                        } else {
                            IntegrityOutcome(CheckResult.NOT_DETECTED, "Single signer")
                        }
                    } else {
                        val pkgInfo = pm.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNATURES)
                        val sigs = pkgInfo.signatures
                        if (sigs != null && sigs.size > 1) {
                            IntegrityOutcome(CheckResult.DETECTED, "${sigs.size} signers detected")
                        } else {
                            IntegrityOutcome(CheckResult.NOT_DETECTED, "Single signer")
                        }
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.ERROR, "${e.javaClass.simpleName}: ${e.message}")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── Runtime Hooking Detection ──

    private fun runHookingDetectionCheck(label: String): IntegrityOutcome {
        return when (label) {
            "Frida server binary" -> {
                val paths = listOf(
                    "/data/local/tmp/frida-server",
                    "/data/local/tmp/re.frida.server",
                )
                val found = paths.filter { File(it).exists() }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Found: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No frida-server binaries found")
                }
            }
            "Frida default port open" -> {
                try {
                    val tcpFile = File("/proc/net/tcp")
                    if (tcpFile.canRead()) {
                        val fridaPortHex = "69A2" // 27042 in hex
                        val found = tcpFile.readLines().any { line ->
                            val parts = line.trim().split("\\s+".toRegex())
                            if (parts.size > 1) {
                                parts[1].endsWith(":$fridaPortHex", ignoreCase = true)
                            } else false
                        }
                        if (found) {
                            IntegrityOutcome(CheckResult.DETECTED, "Port 27042 open in /proc/net/tcp")
                        } else {
                            IntegrityOutcome(CheckResult.NOT_DETECTED, "Port 27042 not open")
                        }
                    } else {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "/proc/net/tcp not readable")
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.ERROR, "Cannot read /proc/net/tcp: ${e.message}")
                }
            }
            "Frida in memory maps" -> {
                try {
                    val mapsFile = File("/proc/self/maps")
                    if (mapsFile.canRead()) {
                        val markers = listOf("frida", "gadget")
                        val matches = mutableListOf<String>()
                        mapsFile.useLines { lines ->
                            lines.forEach { line ->
                                val lower = line.lowercase()
                                for (marker in markers) {
                                    if (lower.contains(marker)) {
                                        matches.add("'$marker' in: ${line.take(80)}")
                                        break
                                    }
                                }
                            }
                        }
                        if (matches.isNotEmpty()) {
                            IntegrityOutcome(CheckResult.DETECTED, matches.joinToString("; "))
                        } else {
                            IntegrityOutcome(CheckResult.NOT_DETECTED, "No frida/gadget strings in /proc/self/maps")
                        }
                    } else {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "/proc/self/maps not readable")
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.ERROR, "Cannot scan /proc/self/maps: ${e.message}")
                }
            }
            "Frida named threads" -> {
                try {
                    val taskDir = File("/proc/self/task")
                    if (taskDir.isDirectory) {
                        val fridaNames = listOf("gmain", "gdbus", "gum-js-loop", "frida")
                        val found = mutableListOf<String>()
                        taskDir.listFiles()?.forEach { tidDir ->
                            val commFile = File(tidDir, "comm")
                            if (commFile.canRead()) {
                                val name = commFile.readText().trim().lowercase()
                                for (fridaName in fridaNames) {
                                    if (name.contains(fridaName)) {
                                        found.add("${tidDir.name}:$name")
                                        break
                                    }
                                }
                            }
                        }
                        if (found.isNotEmpty()) {
                            IntegrityOutcome(CheckResult.DETECTED, "Frida threads: ${found.joinToString()}")
                        } else {
                            IntegrityOutcome(CheckResult.NOT_DETECTED, "No frida thread names found")
                        }
                    } else {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "/proc/self/task not accessible")
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.ERROR, "Cannot scan threads: ${e.message}")
                }
            }
            "Xposed framework files" -> {
                val paths = listOf(
                    "/system/framework/XposedBridge.jar",
                    "/data/adb/lspd",
                    "/data/adb/modules/zygisk_lsposed",
                    "/data/adb/modules/riru_lsposed",
                )
                val found = paths.filter { File(it).exists() }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Found: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No Xposed/LSPosed files found")
                }
            }
            "Xposed class loaded" -> {
                try {
                    Class.forName("de.robv.android.xposed.XposedBridge")
                    IntegrityOutcome(CheckResult.DETECTED, "XposedBridge class is loaded")
                } catch (_: ClassNotFoundException) {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "XposedBridge class not found")
                }
            }
            "Xposed in stack traces" -> {
                val traces = Thread.getAllStackTraces()
                val xposedMarkers = listOf("xposed", "lsposed", "edxposed")
                val evidence = mutableListOf<String>()
                for ((thread, stack) in traces) {
                    for (frame in stack) {
                        val className = frame.className.lowercase()
                        for (marker in xposedMarkers) {
                            if (className.contains(marker)) {
                                evidence.add("${thread.name}: ${frame.className}")
                                break
                            }
                        }
                    }
                }
                if (evidence.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, evidence.take(5).joinToString("; "))
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No Xposed classes in stack traces")
                }
            }
            "Magisk environment detected" -> {
                val evidence = mutableListOf<String>()
                val magiskPaths = listOf("/sbin/.magisk", "/data/adb/magisk")
                for (path in magiskPaths) {
                    if (File(path).exists()) evidence.add("$path exists")
                }
                try {
                    val process = Runtime.getRuntime().exec(arrayOf("which", "magisk"))
                    val reader = BufferedReader(InputStreamReader(process.inputStream))
                    val output = reader.readText().trim()
                    reader.close()
                    process.waitFor()
                    if (output.isNotEmpty()) evidence.add("which magisk: $output")
                } catch (_: Exception) { }
                val magiskPackages = listOf(
                    "com.topjohnwu.magisk",
                    "io.github.vvb2060.magisk",
                    "io.github.huskydg.magisk",
                )
                for (pkg in magiskPackages) {
                    try {
                        val process = Runtime.getRuntime().exec(arrayOf("pm", "list", "packages", pkg))
                        val reader = BufferedReader(InputStreamReader(process.inputStream))
                        val output = reader.readText()
                        reader.close()
                        process.waitFor()
                        if (output.contains("package:$pkg")) evidence.add("Package: $pkg")
                    } catch (_: Exception) { }
                }
                if (evidence.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No Magisk artifacts found")
                }
            }
            "Suspicious native libraries" -> {
                try {
                    val mapsFile = File("/proc/self/maps")
                    if (mapsFile.canRead()) {
                        val markers = listOf("substrate", "cydia", "xhook", "sandhook", "whale", "bytehook")
                        val found = mutableListOf<String>()
                        mapsFile.useLines { lines ->
                            lines.forEach { line ->
                                val lower = line.lowercase()
                                for (marker in markers) {
                                    if (lower.contains(marker)) {
                                        found.add("'$marker' in: ${line.takeLast(60)}")
                                        break
                                    }
                                }
                            }
                        }
                        if (found.isNotEmpty()) {
                            IntegrityOutcome(CheckResult.DETECTED, found.joinToString("; "))
                        } else {
                            IntegrityOutcome(CheckResult.NOT_DETECTED, "No suspicious native libraries in memory maps")
                        }
                    } else {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "/proc/self/maps not readable")
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.ERROR, "Cannot scan /proc/self/maps: ${e.message}")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── Process & Environment ──

    private fun runProcessEnvironmentCheck(label: String, context: Context): IntegrityOutcome {
        return when (label) {
            "Accessibility services active" -> {
                val enabled = Settings.Secure.getString(
                    context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
                )
                if (!enabled.isNullOrEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Active services: $enabled")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No accessibility services enabled")
                }
            }
            "VPN connection active" -> {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val activeNetwork = cm.activeNetwork
                if (activeNetwork != null) {
                    val caps = cm.getNetworkCapabilities(activeNetwork)
                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        IntegrityOutcome(CheckResult.DETECTED, "Active network has TRANSPORT_VPN")
                    } else {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "No VPN transport on active network")
                    }
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No active network")
                }
            }
            "HTTP proxy configured" -> {
                val evidence = mutableListOf<String>()
                val httpHost = System.getProperty("http.proxyHost")
                val httpPort = System.getProperty("http.proxyPort")
                if (!httpHost.isNullOrEmpty()) evidence.add("http.proxyHost=$httpHost:${httpPort ?: "?"}")
                val httpsHost = System.getProperty("https.proxyHost")
                val httpsPort = System.getProperty("https.proxyPort")
                if (!httpsHost.isNullOrEmpty()) evidence.add("https.proxyHost=$httpsHost:${httpsPort ?: "?"}")
                val globalProxy = Settings.Global.getString(context.contentResolver, Settings.Global.HTTP_PROXY)
                if (!globalProxy.isNullOrEmpty() && globalProxy != ":0") evidence.add("Global HTTP_PROXY=$globalProxy")
                if (evidence.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No HTTP/HTTPS proxy configured")
                }
            }
            "Running as root/system UID" -> {
                val uid = android.os.Process.myUid()
                if (uid == 0) {
                    IntegrityOutcome(CheckResult.DETECTED, "UID=$uid (root)")
                } else if (uid == 1000) {
                    IntegrityOutcome(CheckResult.DETECTED, "UID=$uid (system)")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "UID=$uid")
                }
            }
            "Suspicious environment variables" -> {
                val evidence = mutableListOf<String>()
                val ldPreload = System.getenv("LD_PRELOAD")
                if (!ldPreload.isNullOrEmpty()) evidence.add("LD_PRELOAD=$ldPreload")
                val javaOptions = System.getenv("_JAVA_OPTIONS")
                if (!javaOptions.isNullOrEmpty()) evidence.add("_JAVA_OPTIONS=$javaOptions")
                val classpath = System.getenv("CLASSPATH")
                if (classpath != null && (classpath.contains("xposed") || classpath.contains("frida"))) {
                    evidence.add("CLASSPATH contains suspicious entries: $classpath")
                }
                if (evidence.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No suspicious environment variables")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── Hardware Security ──

    private val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"
    private val ATTESTATION_KEY_ALIAS = "ssc_attestation_test"

    private fun generateAttestedKey(): Array<out java.security.cert.Certificate>? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        try { keyStore.deleteEntry(ATTESTATION_KEY_ALIAS) } catch (_: Exception) { }
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(ATTESTATION_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge("ssc_challenge".toByteArray())
                .build()
        )
        keyPairGenerator.generateKeyPair()
        val chain = keyStore.getCertificateChain(ATTESTATION_KEY_ALIAS)
        try { keyStore.deleteEntry(ATTESTATION_KEY_ALIAS) } catch (_: Exception) { }
        return chain
    }

    private fun parseAttestationSecurityLevel(cert: X509Certificate): Int? {
        val extensionValue = cert.getExtensionValue(ATTESTATION_EXTENSION_OID) ?: return null
        return try {
            var offset = 0
            // Unwrap outer OCTET STRING (tag 0x04)
            if (extensionValue[offset].toInt() and 0xFF != 0x04) return null
            offset++
            offset += derLengthSize(extensionValue, offset)

            // SEQUENCE (tag 0x30)
            if (extensionValue[offset].toInt() and 0xFF != 0x30) return null
            offset++
            offset += derLengthSize(extensionValue, offset)

            // INTEGER attestationVersion (tag 0x02)
            if (extensionValue[offset].toInt() and 0xFF != 0x02) return null
            offset++
            val intLen = derReadLength(extensionValue, offset)
            offset += derLengthSize(extensionValue, offset) + intLen

            // ENUMERATED attestationSecurityLevel (tag 0x0A)
            if (extensionValue[offset].toInt() and 0xFF != 0x0A) return null
            offset++
            offset += derLengthSize(extensionValue, offset)
            extensionValue[offset].toInt() and 0xFF
        } catch (_: Exception) {
            null
        }
    }

    private fun derReadLength(data: ByteArray, offset: Int): Int {
        val first = data[offset].toInt() and 0xFF
        if (first < 0x80) return first
        val numBytes = first and 0x7F
        var length = 0
        for (i in 1..numBytes) {
            length = (length shl 8) or (data[offset + i].toInt() and 0xFF)
        }
        return length
    }

    private fun derLengthSize(data: ByteArray, offset: Int): Int {
        val first = data[offset].toInt() and 0xFF
        return if (first < 0x80) 1 else 1 + (first and 0x7F)
    }

    private fun runHardwareSecurityCheck(label: String, context: Context): IntegrityOutcome {
        return when (label) {
            "Key attestation supported" -> {
                try {
                    val chain = generateAttestedKey()
                    if (chain == null || chain.isEmpty()) {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "No attestation certificate chain returned")
                    } else {
                        val leaf = chain[0] as X509Certificate
                        val hasExtension = leaf.getExtensionValue(ATTESTATION_EXTENSION_OID) != null
                        if (hasExtension) {
                            IntegrityOutcome(CheckResult.DETECTED, "Attestation chain has ${chain.size} cert(s), extension OID present")
                        } else {
                            IntegrityOutcome(CheckResult.NOT_DETECTED, "Chain has ${chain.size} cert(s) but attestation extension missing")
                        }
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Key attestation not available: ${e.javaClass.simpleName}: ${e.message?.take(100)}")
                }
            }
            "Attestation backed by hardware" -> {
                try {
                    val chain = generateAttestedKey()
                    if (chain == null || chain.isEmpty()) {
                        return IntegrityOutcome(CheckResult.NOT_DETECTED, "No attestation chain available")
                    }
                    val leaf = chain[0] as X509Certificate
                    val securityLevel = parseAttestationSecurityLevel(leaf)
                    when (securityLevel) {
                        null -> IntegrityOutcome(CheckResult.NOT_DETECTED, "Could not parse attestation extension")
                        0 -> IntegrityOutcome(CheckResult.NOT_DETECTED, "Security level: Software (not hardware-backed)")
                        1 -> IntegrityOutcome(CheckResult.DETECTED, "Security level: TrustedEnvironment (TEE)")
                        2 -> IntegrityOutcome(CheckResult.DETECTED, "Security level: StrongBox")
                        else -> IntegrityOutcome(CheckResult.NOT_DETECTED, "Unknown security level: $securityLevel")
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Cannot check: ${e.javaClass.simpleName}: ${e.message?.take(100)}")
                }
            }
            "Google attestation root certificate" -> {
                try {
                    val chain = generateAttestedKey()
                    if (chain == null || chain.size < 2) {
                        return IntegrityOutcome(CheckResult.NOT_DETECTED, "Attestation chain too short (${chain?.size ?: 0} cert(s))")
                    }
                    val root = chain.last() as X509Certificate
                    val subject = root.subjectX500Principal.name
                    val isGoogle = subject.contains("Google", ignoreCase = true) &&
                        subject.contains("Attestation", ignoreCase = true)
                    if (isGoogle) {
                        IntegrityOutcome(CheckResult.DETECTED, "Root: $subject")
                    } else {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "Root is not Google attestation: $subject")
                    }
                } catch (e: Exception) {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Cannot check: ${e.javaClass.simpleName}: ${e.message?.take(100)}")
                }
            }
            "StrongBox keystore available" -> {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                    return IntegrityOutcome(CheckResult.NOT_DETECTED, "StrongBox requires API 28+, device is API ${Build.VERSION.SDK_INT}")
                }
                try {
                    val alias = "ssc_strongbox_test"
                    val keyStore = KeyStore.getInstance("AndroidKeyStore")
                    keyStore.load(null)
                    try { keyStore.deleteEntry(alias) } catch (_: Exception) { }
                    val keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
                    )
                    keyPairGenerator.initialize(
                        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setIsStrongBoxBacked(true)
                            .build()
                    )
                    keyPairGenerator.generateKeyPair()
                    try { keyStore.deleteEntry(alias) } catch (_: Exception) { }
                    IntegrityOutcome(CheckResult.DETECTED, "StrongBox key generation succeeded")
                } catch (_: StrongBoxUnavailableException) {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "StrongBox not available on this device")
                } catch (e: Exception) {
                    if (e.cause is StrongBoxUnavailableException) {
                        IntegrityOutcome(CheckResult.NOT_DETECTED, "StrongBox not available on this device")
                    } else {
                        IntegrityOutcome(CheckResult.ERROR, "${e.javaClass.simpleName}: ${e.message?.take(100)}")
                    }
                }
            }
            "Biometric hardware present" -> {
                val pm = context.packageManager
                val features = mutableListOf<String>()
                if (pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) features.add("fingerprint")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    if (pm.hasSystemFeature(PackageManager.FEATURE_FACE)) features.add("face")
                    if (pm.hasSystemFeature(PackageManager.FEATURE_IRIS)) features.add("iris")
                }
                if (features.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Biometric hardware: ${features.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No biometric hardware features found")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── Screen Capture Protection ──

    private fun runScreenCaptureProtectionCheck(label: String, context: Context): IntegrityOutcome {
        return when (label) {
            "FLAG_SECURE bypass modules (Xposed)" -> {
                val bypassPackages = listOf(
                    "com.varuns2002.disable_flag_secure",
                    "fi.veekan.disableflagsecure",
                    "com.displaysecure",
                    "com.xstar97.disableflagsecure",
                )
                val pm = context.packageManager
                val found = mutableListOf<String>()
                for (pkg in bypassPackages) {
                    try {
                        pm.getPackageInfo(pkg, 0)
                        found.add(pkg)
                    } catch (_: Exception) { }
                }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Bypass packages: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No known FLAG_SECURE bypass packages found")
                }
            }
            "FLAG_SECURE bypass modules (Magisk)" -> {
                val evidence = mutableListOf<String>()
                val knownModules = listOf(
                    "/data/adb/modules/DisableFlagSecure",
                    "/data/adb/modules/disableflagsecure",
                    "/data/adb/modules/disable_flag_secure",
                )
                for (path in knownModules) {
                    if (File(path).exists()) evidence.add("$path exists")
                }
                try {
                    val modulesDir = File("/data/adb/modules")
                    if (modulesDir.isDirectory) {
                        val markers = listOf("flagsecure", "flag_secure", "screensecurity", "screencap")
                        modulesDir.listFiles()?.forEach { moduleDir ->
                            val name = moduleDir.name.lowercase()
                            for (marker in markers) {
                                if (name.contains(marker)) {
                                    evidence.add("Suspicious module: ${moduleDir.name}")
                                    break
                                }
                            }
                        }
                    }
                } catch (_: Exception) { }
                if (evidence.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No FLAG_SECURE bypass Magisk modules found")
                }
            }
            "Bypass classes loaded" -> {
                val bypassClasses = listOf(
                    "de.robv.android.xposed.XposedBridge",
                    "com.varuns2002.disable_flag_secure.MainHook",
                    "fi.veekan.disableflagsecure.DisableSecureFlag",
                )
                val loaded = mutableListOf<String>()
                for (cls in bypassClasses) {
                    try {
                        Class.forName(cls)
                        loaded.add(cls)
                    } catch (_: ClassNotFoundException) { }
                }
                // Also scan stack traces for flag_secure/flagsecure related hooks
                val traces = Thread.getAllStackTraces()
                val hookMarkers = listOf("flagsecure", "flag_secure", "disablesecure")
                for ((thread, stack) in traces) {
                    for (frame in stack) {
                        val className = frame.className.lowercase()
                        for (marker in hookMarkers) {
                            if (className.contains(marker)) {
                                loaded.add("${thread.name}: ${frame.className}")
                                break
                            }
                        }
                    }
                }
                if (loaded.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, loaded.joinToString("; "))
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No bypass classes loaded or in stack traces")
                }
            }
            "Screen recording apps installed" -> {
                val recorderPackages = listOf(
                    "com.kimcy929.screenrecorder",
                    "com.hecorat.screenrecorder.free",
                    "com.rec.screen.recorder",
                    "com.rsstudio.screen.recorder",
                    "screenrecorder.suspended.app",
                )
                val pm = context.packageManager
                val found = mutableListOf<String>()
                for (pkg in recorderPackages) {
                    try {
                        pm.getPackageInfo(pkg, 0)
                        found.add(pkg)
                    } catch (_: Exception) { }
                }
                if (found.isNotEmpty()) {
                    IntegrityOutcome(CheckResult.DETECTED, "Recorder apps: ${found.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "No known screen recording apps found")
                }
            }
            "Virtual displays active" -> {
                val dm = context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
                val displays = dm.displays
                val virtual = displays.filter { display ->
                    display.displayId != Display.DEFAULT_DISPLAY &&
                        (display.flags and Display.FLAG_PRESENTATION) != 0 ||
                        display.name?.lowercase()?.let {
                            it.contains("virtual") || it.contains("overlay") || it.contains("mirror")
                        } == true
                }
                if (virtual.isNotEmpty()) {
                    val names = virtual.map { "${it.name} (id=${it.displayId})" }
                    IntegrityOutcome(CheckResult.DETECTED, "Non-default displays: ${names.joinToString()}")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "${displays.size} display(s), all built-in")
                }
            }
            "Overlay drawing permitted" -> {
                if (Settings.canDrawOverlays(context)) {
                    IntegrityOutcome(CheckResult.DETECTED, "SYSTEM_ALERT_WINDOW granted — other apps can draw over this app")
                } else {
                    IntegrityOutcome(CheckResult.NOT_DETECTED, "Overlay permission not granted")
                }
            }
            else -> IntegrityOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    // ── Utility ──

    private fun getSystemProperty(key: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readText().trim()
            reader.close()
            process.waitFor()
            value
        } catch (_: Exception) {
            ""
        }
    }
}
