package com.khasmek.simplesecuritychecks.checker

import android.util.Base64
import com.khasmek.simplesecuritychecks.model.CheckCategory
import com.khasmek.simplesecuritychecks.model.CheckItem
import com.khasmek.simplesecuritychecks.model.CheckResult
import okhttp3.CertificatePinner
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.IOException
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

private data class CheckOutcome(val result: CheckResult, val detail: String)

object SslPinningChecker {

    fun getDefaultCategories(): List<CheckCategory> = listOf(
        CheckCategory(
            id = "okhttp_certificate_pinner",
            name = "OkHttp CertificatePinner",
            description = "Certificate pinning via OkHttp CertificatePinner",
            items = listOf(
                CheckItem("Pin valid SHA-256"),
                CheckItem("Pin wrong hash (expect block)"),
                CheckItem("Pin with backup hash"),
            )
        ),
        CheckCategory(
            id = "custom_trust_manager",
            name = "Custom TrustManager",
            description = "Custom X509TrustManager validation checks",
            items = listOf(
                CheckItem("Strict cert validation"),
                CheckItem("System-only trust (reject user CAs)"),
            )
        ),
        CheckCategory(
            id = "https_url_connection_pinning",
            name = "HttpsURLConnection Pinning",
            description = "Public key pinning via HttpsURLConnection",
            items = listOf(
                CheckItem("Public key pinning"),
            )
        ),
        CheckCategory(
            id = "pinning_bypass_detection",
            name = "Pinning Bypass Detection",
            description = "Detect common SSL pinning bypass tools and techniques",
            items = listOf(
                CheckItem("Proxy CA in user trust store"),
                CheckItem("Frida server running"),
                CheckItem("Xposed framework installed"),
                CheckItem("Magisk SSL bypass modules"),
            )
        ),
    )

    fun runChecks(categories: List<CheckCategory>, targetUrl: String): List<CheckCategory> {
        return categories.map { category ->
            val checkedItems = category.items.map { item ->
                if (!item.enabled) {
                    item.copy(result = null, detail = null)
                } else {
                    val outcome = runSingleCheck(category.id, item.label, targetUrl)
                    item.copy(result = outcome.result, detail = outcome.detail)
                }
            }
            category.copy(items = checkedItems)
        }
    }

    private fun runSingleCheck(categoryId: String, label: String, targetUrl: String): CheckOutcome {
        return try {
            when (categoryId) {
                "okhttp_certificate_pinner" -> runOkHttpPinningCheck(label, targetUrl)
                "custom_trust_manager" -> runTrustManagerCheck(label, targetUrl)
                "https_url_connection_pinning" -> runUrlConnectionPinningCheck(targetUrl)
                "pinning_bypass_detection" -> runBypassDetectionCheck(label)
                else -> CheckOutcome(CheckResult.ERROR, "Unknown category")
            }
        } catch (e: Exception) {
            CheckOutcome(CheckResult.ERROR, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun computeSpkiPin(cert: X509Certificate): String {
        val spki = cert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256").digest(spki)
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    private fun fetchCertPins(urlString: String): List<String> {
        val url = URL(urlString)
        val conn = url.openConnection() as HttpsURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000
        conn.requestMethod = "HEAD"
        try {
            conn.connect()
            val certs = conn.serverCertificates
            return certs.filterIsInstance<X509Certificate>().map { computeSpkiPin(it) }
        } finally {
            conn.disconnect()
        }
    }

    private fun buildIsolatedClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .connectionPool(ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
    }

    private fun runOkHttpPinningCheck(label: String, targetUrl: String): CheckOutcome {
        val url = URL(targetUrl)
        val host = url.host
        val pins = fetchCertPins(targetUrl)
        if (pins.isEmpty()) return CheckOutcome(CheckResult.ERROR, "Could not fetch certificate pins from $host")

        return when (label) {
            "Pin valid SHA-256" -> {
                val pin = pins[0]
                val pinner = CertificatePinner.Builder()
                    .add(host, "sha256/$pin")
                    .build()
                val client = buildIsolatedClient().newBuilder()
                    .certificatePinner(pinner)
                    .build()
                val request = Request.Builder().url(targetUrl).head().build()
                client.newCall(request).execute().use { response ->
                    if (response.isSuccessful) {
                        CheckOutcome(CheckResult.DETECTED, "Pinned request succeeded (HTTP ${response.code}), pin=sha256/${pin.take(12)}...")
                    } else {
                        CheckOutcome(CheckResult.ERROR, "HTTP ${response.code} with valid pin")
                    }
                }
            }
            "Pin wrong hash (expect block)" -> {
                val bogusPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                val pinner = CertificatePinner.Builder()
                    .add(host, bogusPin)
                    .build()
                val client = buildIsolatedClient().newBuilder()
                    .certificatePinner(pinner)
                    .build()
                val request = Request.Builder().url(targetUrl).head().build()
                try {
                    client.newCall(request).execute().use { response ->
                        CheckOutcome(
                            CheckResult.NOT_DETECTED,
                            "Request succeeded (HTTP ${response.code}) despite wrong pin — pinning was bypassed"
                        )
                    }
                } catch (e: IOException) {
                    CheckOutcome(
                        CheckResult.DETECTED,
                        "Pinning blocked request: ${e.javaClass.simpleName}"
                    )
                }
            }
            "Pin with backup hash" -> {
                if (pins.size < 2) return CheckOutcome(CheckResult.ERROR, "Only ${pins.size} cert(s) in chain, need at least 2 for backup pin test")
                val bogusPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                val backupPin = "sha256/${pins[1]}"
                val pinner = CertificatePinner.Builder()
                    .add(host, bogusPin)
                    .add(host, backupPin)
                    .build()
                val client = buildIsolatedClient().newBuilder()
                    .certificatePinner(pinner)
                    .build()
                val request = Request.Builder().url(targetUrl).head().build()
                client.newCall(request).execute().use { response ->
                    if (response.isSuccessful) {
                        CheckOutcome(CheckResult.DETECTED, "Backup pin matched intermediate cert (HTTP ${response.code})")
                    } else {
                        CheckOutcome(CheckResult.ERROR, "HTTP ${response.code} with backup pin")
                    }
                }
            }
            else -> CheckOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    private fun runTrustManagerCheck(label: String, targetUrl: String): CheckOutcome {
        return when (label) {
            "Strict cert validation" -> {
                val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                tmf.init(null as KeyStore?)
                val systemTm = tmf.trustManagers
                    .filterIsInstance<X509TrustManager>()
                    .first()

                var trustManagerInvoked = false
                val wrappedTm = object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                        systemTm.checkClientTrusted(chain, authType)
                    }

                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                        trustManagerInvoked = true
                        systemTm.checkServerTrusted(chain, authType)
                    }

                    override fun getAcceptedIssuers(): Array<X509Certificate> = systemTm.acceptedIssuers
                }

                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, arrayOf(wrappedTm), null)

                val client = OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.socketFactory, wrappedTm)
                    .connectionPool(ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(10, TimeUnit.SECONDS)
                    .build()

                val request = Request.Builder().url(targetUrl).head().build()
                client.newCall(request).execute().use { response ->
                    if (trustManagerInvoked) {
                        CheckOutcome(CheckResult.DETECTED, "Custom TrustManager.checkServerTrusted() was invoked (HTTP ${response.code})")
                    } else {
                        CheckOutcome(CheckResult.NOT_DETECTED, "TrustManager was NOT invoked — possible session reuse or bypass (HTTP ${response.code})")
                    }
                }
            }
            "System-only trust (reject user CAs)" -> {
                val systemKs = KeyStore.getInstance("AndroidCAStore")
                systemKs.load(null)
                val filteredKs = KeyStore.getInstance(KeyStore.getDefaultType())
                filteredKs.load(null, null)

                var index = 0
                for (alias in systemKs.aliases()) {
                    if (alias.startsWith("system:")) {
                        val cert = systemKs.getCertificate(alias)
                        filteredKs.setCertificateEntry("system_$index", cert)
                        index++
                    }
                }

                val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                tmf.init(filteredKs)
                val systemOnlyTm = tmf.trustManagers
                    .filterIsInstance<X509TrustManager>()
                    .first()

                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, arrayOf(systemOnlyTm), null)

                val client = OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.socketFactory, systemOnlyTm)
                    .connectionPool(ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(10, TimeUnit.SECONDS)
                    .build()

                val request = Request.Builder().url(targetUrl).head().build()
                try {
                    client.newCall(request).execute().use { response ->
                        CheckOutcome(CheckResult.DETECTED, "Connected with system-only CAs ($index system certs loaded, HTTP ${response.code})")
                    }
                } catch (e: javax.net.ssl.SSLHandshakeException) {
                    CheckOutcome(CheckResult.NOT_DETECTED, "Handshake failed with system-only CAs — likely needs user CA: ${e.message?.take(100)}")
                }
            }
            else -> CheckOutcome(CheckResult.ERROR, "Unknown check")
        }
    }

    private fun runUrlConnectionPinningCheck(targetUrl: String): CheckOutcome {
        val pins = fetchCertPins(targetUrl)
        if (pins.isEmpty()) return CheckOutcome(CheckResult.ERROR, "Could not fetch certificate pins")
        val expectedPin = pins[0]

        val url = URL(targetUrl)
        val conn = url.openConnection() as HttpsURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000
        conn.requestMethod = "HEAD"
        try {
            conn.connect()
            val serverCerts = conn.serverCertificates
            val leafCert = serverCerts.filterIsInstance<X509Certificate>().firstOrNull()
                ?: return CheckOutcome(CheckResult.ERROR, "No X509Certificate in server certs")
            val actualPin = computeSpkiPin(leafCert)
            return if (actualPin == expectedPin) {
                CheckOutcome(CheckResult.DETECTED, "Leaf cert pin matches: sha256/${actualPin.take(12)}...")
            } else {
                CheckOutcome(CheckResult.NOT_DETECTED, "Pin mismatch — expected sha256/${expectedPin.take(12)}..., got sha256/${actualPin.take(12)}...")
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun runBypassDetectionCheck(label: String): CheckOutcome {
        return when (label) {
            "Proxy CA in user trust store" -> {
                try {
                    val ks = KeyStore.getInstance("AndroidCAStore")
                    ks.load(null)
                    val userAliases = ks.aliases().asSequence().filter { it.startsWith("user:") }.toList()
                    if (userAliases.isNotEmpty()) {
                        CheckOutcome(CheckResult.DETECTED, "Found ${userAliases.size} user CA(s)")
                    } else {
                        CheckOutcome(CheckResult.NOT_DETECTED, "No user CAs in trust store")
                    }
                } catch (e: Exception) {
                    CheckOutcome(CheckResult.ERROR, "${e.javaClass.simpleName}: ${e.message}")
                }
            }
            "Frida server running" -> {
                val evidence = mutableListOf<String>()
                if (File("/data/local/tmp/frida-server").exists()) {
                    evidence.add("/data/local/tmp/frida-server exists")
                }
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
                        if (found) evidence.add("Port 27042 open in /proc/net/tcp")
                    }
                } catch (_: Exception) { }
                try {
                    val mapsFile = File("/proc/self/maps")
                    if (mapsFile.canRead()) {
                        val found = mapsFile.useLines { lines ->
                            lines.any { it.contains("frida", ignoreCase = true) }
                        }
                        if (found) evidence.add("'frida' found in /proc/self/maps")
                    }
                } catch (_: Exception) { }
                if (evidence.isNotEmpty()) {
                    CheckOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    CheckOutcome(CheckResult.NOT_DETECTED, "No frida-server binary, port 27042 closed, no frida in memory maps")
                }
            }
            "Xposed framework installed" -> {
                val evidence = mutableListOf<String>()
                val checked = mutableListOf<String>()
                val xposedPaths = listOf(
                    "/system/framework/XposedBridge.jar",
                    "/data/adb/lspd",
                    "/data/adb/modules/zygisk_lsposed",
                    "/data/adb/modules/riru_lsposed",
                )
                for (path in xposedPaths) {
                    if (File(path).exists()) {
                        evidence.add("$path exists")
                    } else {
                        checked.add(path)
                    }
                }
                try {
                    Class.forName("de.robv.android.xposed.XposedBridge")
                    evidence.add("XposedBridge class loaded")
                } catch (_: ClassNotFoundException) {
                    checked.add("XposedBridge class not found")
                }
                if (evidence.isNotEmpty()) {
                    CheckOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    CheckOutcome(CheckResult.NOT_DETECTED, "Checked: ${checked.joinToString(", ")}")
                }
            }
            "Magisk SSL bypass modules" -> {
                val evidence = mutableListOf<String>()
                val checked = mutableListOf<String>()
                val knownModules = listOf(
                    "/data/adb/modules/movecert",
                    "/data/adb/modules/MagiskTrustUserCerts",
                    "/data/adb/modules/trustusercerts",
                )
                for (path in knownModules) {
                    if (File(path).exists()) {
                        evidence.add("$path exists")
                    } else {
                        checked.add(path)
                    }
                }
                try {
                    val modulesDir = File("/data/adb/modules")
                    if (modulesDir.isDirectory) {
                        val suspiciousNames = listOf("cert", "ssl", "trust", "pin")
                        modulesDir.listFiles()?.forEach { moduleDir ->
                            val name = moduleDir.name.lowercase()
                            if (suspiciousNames.any { name.contains(it) }) {
                                evidence.add("Suspicious module: ${moduleDir.name}")
                            }
                        }
                        if (evidence.isEmpty()) checked.add("/data/adb/modules/ scanned, no suspicious names")
                    } else {
                        checked.add("/data/adb/modules/ not accessible")
                    }
                } catch (_: Exception) {
                    checked.add("/data/adb/modules/ not accessible")
                }
                if (evidence.isNotEmpty()) {
                    CheckOutcome(CheckResult.DETECTED, evidence.joinToString("; "))
                } else {
                    CheckOutcome(CheckResult.NOT_DETECTED, "Checked: ${checked.joinToString(", ")}")
                }
            }
            else -> CheckOutcome(CheckResult.ERROR, "Unknown check")
        }
    }
}
