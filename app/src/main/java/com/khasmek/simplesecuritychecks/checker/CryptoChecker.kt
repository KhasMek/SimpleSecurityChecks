package com.khasmek.simplesecuritychecks.checker

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.khasmek.simplesecuritychecks.model.CheckCategory
import com.khasmek.simplesecuritychecks.model.CheckItem
import com.khasmek.simplesecuritychecks.model.CheckResult
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object CryptoChecker {

    fun getDefaultCategories(): List<CheckCategory> = listOf(
        CheckCategory(
            id = "symmetric_encryption",
            name = "Symmetric Encryption",
            description = "AES and DES encryption/decryption operations",
            items = listOf(
                CheckItem("AES-CBC-128"),
                CheckItem("AES-CBC-256"),
                CheckItem("AES-GCM-128"),
                CheckItem("AES-GCM-256"),
                CheckItem("DES"),
                CheckItem("DESede (3DES)"),
            )
        ),
        CheckCategory(
            id = "asymmetric_encryption",
            name = "Asymmetric Encryption",
            description = "RSA encryption/decryption operations",
            items = listOf(
                CheckItem("RSA-2048"),
                CheckItem("RSA-4096"),
            )
        ),
        CheckCategory(
            id = "hashing",
            name = "Hashing",
            description = "Cryptographic hash functions",
            items = listOf(
                CheckItem("MD5"),
                CheckItem("SHA-1"),
                CheckItem("SHA-256"),
                CheckItem("SHA-384"),
                CheckItem("SHA-512"),
            )
        ),
        CheckCategory(
            id = "hmac",
            name = "HMAC",
            description = "Hash-based message authentication codes",
            items = listOf(
                CheckItem("HMAC-MD5"),
                CheckItem("HMAC-SHA1"),
                CheckItem("HMAC-SHA256"),
                CheckItem("HMAC-SHA512"),
            )
        ),
        CheckCategory(
            id = "key_derivation",
            name = "Key Derivation",
            description = "Password-based key derivation functions",
            items = listOf(
                CheckItem("PBKDF2WithHmacSHA1"),
                CheckItem("PBKDF2WithHmacSHA256"),
            )
        ),
        CheckCategory(
            id = "digital_signatures",
            name = "Digital Signatures",
            description = "Sign and verify operations",
            items = listOf(
                CheckItem("SHA256withRSA"),
                CheckItem("SHA256withECDSA"),
            )
        ),
        CheckCategory(
            id = "secure_random",
            name = "Secure Random",
            description = "Cryptographically secure random number generation",
            items = listOf(
                CheckItem("SecureRandom byte generation"),
            )
        ),
        CheckCategory(
            id = "android_keystore",
            name = "Android Keystore",
            description = "Hardware-backed key storage operations",
            items = listOf(
                CheckItem("AES key in Keystore"),
                CheckItem("RSA key in Keystore"),
                CheckItem("EC key in Keystore"),
            )
        ),
    )

    fun runChecks(categories: List<CheckCategory>): List<CheckCategory> {
        return categories.map { category ->
            val checkedItems = category.items.map { item ->
                if (!item.enabled) {
                    item.copy(result = null)
                } else {
                    val result = runSingleCheck(category.id, item.label)
                    item.copy(result = result)
                }
            }
            category.copy(items = checkedItems)
        }
    }

    private fun runSingleCheck(categoryId: String, label: String): CheckResult {
        return try {
            when (categoryId) {
                "symmetric_encryption" -> runSymmetricEncryption(label)
                "asymmetric_encryption" -> runAsymmetricEncryption(label)
                "hashing" -> runHashing(label)
                "hmac" -> runHmac(label)
                "key_derivation" -> runKeyDerivation(label)
                "digital_signatures" -> runDigitalSignature(label)
                "secure_random" -> runSecureRandom()
                "android_keystore" -> runKeystoreOperation(label)
                else -> CheckResult.ERROR
            }
        } catch (_: Exception) {
            CheckResult.ERROR
        }
    }

    private fun runSymmetricEncryption(label: String): CheckResult {
        val testData = "SimpleSecurityChecks test data".toByteArray()
        return when (label) {
            "AES-CBC-128" -> {
                val keyGen = KeyGenerator.getInstance("AES")
                keyGen.init(128)
                val key = keyGen.generateKey()
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val iv = cipher.iv
                val encrypted = cipher.doFinal(testData)
                cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
                val decrypted = cipher.doFinal(encrypted)
                if (decrypted.contentEquals(testData)) CheckResult.DETECTED else CheckResult.ERROR
            }
            "AES-CBC-256" -> {
                val keyGen = KeyGenerator.getInstance("AES")
                keyGen.init(256)
                val key = keyGen.generateKey()
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val iv = cipher.iv
                val encrypted = cipher.doFinal(testData)
                cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
                val decrypted = cipher.doFinal(encrypted)
                if (decrypted.contentEquals(testData)) CheckResult.DETECTED else CheckResult.ERROR
            }
            "AES-GCM-128" -> {
                val keyGen = KeyGenerator.getInstance("AES")
                keyGen.init(128)
                val key = keyGen.generateKey()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val iv = cipher.iv
                val encrypted = cipher.doFinal(testData)
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                val decrypted = cipher.doFinal(encrypted)
                if (decrypted.contentEquals(testData)) CheckResult.DETECTED else CheckResult.ERROR
            }
            "AES-GCM-256" -> {
                val keyGen = KeyGenerator.getInstance("AES")
                keyGen.init(256)
                val key = keyGen.generateKey()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val iv = cipher.iv
                val encrypted = cipher.doFinal(testData)
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                val decrypted = cipher.doFinal(encrypted)
                if (decrypted.contentEquals(testData)) CheckResult.DETECTED else CheckResult.ERROR
            }
            "DES" -> {
                val keyGen = KeyGenerator.getInstance("DES")
                keyGen.init(56)
                val key = keyGen.generateKey()
                val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val iv = cipher.iv
                val encrypted = cipher.doFinal(testData)
                cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
                val decrypted = cipher.doFinal(encrypted)
                if (decrypted.contentEquals(testData)) CheckResult.DETECTED else CheckResult.ERROR
            }
            "DESede (3DES)" -> {
                val keyGen = KeyGenerator.getInstance("DESede")
                keyGen.init(168)
                val key = keyGen.generateKey()
                val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val iv = cipher.iv
                val encrypted = cipher.doFinal(testData)
                cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
                val decrypted = cipher.doFinal(encrypted)
                if (decrypted.contentEquals(testData)) CheckResult.DETECTED else CheckResult.ERROR
            }
            else -> CheckResult.ERROR
        }
    }

    private fun runAsymmetricEncryption(label: String): CheckResult {
        val testData = "SimpleSecurityChecks test".toByteArray()
        val keySize = when (label) {
            "RSA-2048" -> 2048
            "RSA-4096" -> 4096
            else -> return CheckResult.ERROR
        }
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(keySize)
        val keyPair = keyPairGen.generateKeyPair()
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
        val encrypted = cipher.doFinal(testData)
        cipher.init(Cipher.DECRYPT_MODE, keyPair.private)
        val decrypted = cipher.doFinal(encrypted)
        return if (decrypted.contentEquals(testData)) CheckResult.DETECTED else CheckResult.ERROR
    }

    private fun runHashing(label: String): CheckResult {
        val testData = "SimpleSecurityChecks test data".toByteArray()
        val algorithm = when (label) {
            "MD5" -> "MD5"
            "SHA-1" -> "SHA-1"
            "SHA-256" -> "SHA-256"
            "SHA-384" -> "SHA-384"
            "SHA-512" -> "SHA-512"
            else -> return CheckResult.ERROR
        }
        val digest = MessageDigest.getInstance(algorithm)
        val hash = digest.digest(testData)
        return if (hash.isNotEmpty()) CheckResult.DETECTED else CheckResult.ERROR
    }

    private fun runHmac(label: String): CheckResult {
        val testData = "SimpleSecurityChecks test data".toByteArray()
        val algorithm = when (label) {
            "HMAC-MD5" -> "HmacMD5"
            "HMAC-SHA1" -> "HmacSHA1"
            "HMAC-SHA256" -> "HmacSHA256"
            "HMAC-SHA512" -> "HmacSHA512"
            else -> return CheckResult.ERROR
        }
        val keyGen = KeyGenerator.getInstance(algorithm)
        val key = keyGen.generateKey()
        val mac = Mac.getInstance(algorithm)
        mac.init(key)
        val hmacResult = mac.doFinal(testData)
        return if (hmacResult.isNotEmpty()) CheckResult.DETECTED else CheckResult.ERROR
    }

    private fun runKeyDerivation(label: String): CheckResult {
        val password = "TestPassword123".toCharArray()
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val algorithm = when (label) {
            "PBKDF2WithHmacSHA1" -> "PBKDF2WithHmacSHA1"
            "PBKDF2WithHmacSHA256" -> "PBKDF2WithHmacSHA256"
            else -> return CheckResult.ERROR
        }
        val spec = PBEKeySpec(password, salt, 10000, 256)
        val factory = SecretKeyFactory.getInstance(algorithm)
        val key = factory.generateSecret(spec)
        return if (key.encoded.isNotEmpty()) CheckResult.DETECTED else CheckResult.ERROR
    }

    private fun runDigitalSignature(label: String): CheckResult {
        val testData = "SimpleSecurityChecks test data".toByteArray()
        return when (label) {
            "SHA256withRSA" -> {
                val keyPairGen = KeyPairGenerator.getInstance("RSA")
                keyPairGen.initialize(2048)
                val keyPair = keyPairGen.generateKeyPair()
                val signer = Signature.getInstance("SHA256withRSA")
                signer.initSign(keyPair.private)
                signer.update(testData)
                val signature = signer.sign()
                val verifier = Signature.getInstance("SHA256withRSA")
                verifier.initVerify(keyPair.public)
                verifier.update(testData)
                if (verifier.verify(signature)) CheckResult.DETECTED else CheckResult.ERROR
            }
            "SHA256withECDSA" -> {
                val keyPairGen = KeyPairGenerator.getInstance("EC")
                keyPairGen.initialize(ECGenParameterSpec("secp256r1"))
                val keyPair = keyPairGen.generateKeyPair()
                val signer = Signature.getInstance("SHA256withECDSA")
                signer.initSign(keyPair.private)
                signer.update(testData)
                val signature = signer.sign()
                val verifier = Signature.getInstance("SHA256withECDSA")
                verifier.initVerify(keyPair.public)
                verifier.update(testData)
                if (verifier.verify(signature)) CheckResult.DETECTED else CheckResult.ERROR
            }
            else -> CheckResult.ERROR
        }
    }

    private fun runSecureRandom(): CheckResult {
        val random = SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return if (bytes.any { it != 0.toByte() }) CheckResult.DETECTED else CheckResult.ERROR
    }

    private fun runKeystoreOperation(label: String): CheckResult {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val testAlias = "ssc_test_${System.nanoTime()}"
        try {
            return when (label) {
                "AES key in Keystore" -> {
                    val keyGen = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES,
                        "AndroidKeyStore"
                    )
                    keyGen.init(
                        KeyGenParameterSpec.Builder(
                            testAlias,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                        )
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setKeySize(256)
                            .build()
                    )
                    val key = keyGen.generateKey()
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, key)
                    val iv = cipher.iv
                    val testData = "Keystore AES test".toByteArray()
                    val encrypted = cipher.doFinal(testData)
                    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                    val decrypted = cipher.doFinal(encrypted)
                    if (decrypted.contentEquals(testData)) CheckResult.DETECTED else CheckResult.ERROR
                }
                "RSA key in Keystore" -> {
                    val keyPairGen = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_RSA,
                        "AndroidKeyStore"
                    )
                    keyPairGen.initialize(
                        KeyGenParameterSpec.Builder(
                            testAlias,
                            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                        )
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                            .setKeySize(2048)
                            .build()
                    )
                    val keyPair = keyPairGen.generateKeyPair()
                    val testData = "Keystore RSA test".toByteArray()
                    val signer = Signature.getInstance("SHA256withRSA")
                    signer.initSign(keyPair.private)
                    signer.update(testData)
                    val signature = signer.sign()
                    val verifier = Signature.getInstance("SHA256withRSA")
                    verifier.initVerify(keyPair.public)
                    verifier.update(testData)
                    if (verifier.verify(signature)) CheckResult.DETECTED else CheckResult.ERROR
                }
                "EC key in Keystore" -> {
                    val keyPairGen = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC,
                        "AndroidKeyStore"
                    )
                    keyPairGen.initialize(
                        KeyGenParameterSpec.Builder(
                            testAlias,
                            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                        )
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .build()
                    )
                    val keyPair = keyPairGen.generateKeyPair()
                    val testData = "Keystore EC test".toByteArray()
                    val signer = Signature.getInstance("SHA256withECDSA")
                    signer.initSign(keyPair.private)
                    signer.update(testData)
                    val signature = signer.sign()
                    val verifier = Signature.getInstance("SHA256withECDSA")
                    verifier.initVerify(keyPair.public)
                    verifier.update(testData)
                    if (verifier.verify(signature)) CheckResult.DETECTED else CheckResult.ERROR
                }
                else -> CheckResult.ERROR
            }
        } finally {
            try {
                keyStore.deleteEntry(testAlias)
            } catch (_: Exception) {
                // Best-effort cleanup
            }
        }
    }
}
