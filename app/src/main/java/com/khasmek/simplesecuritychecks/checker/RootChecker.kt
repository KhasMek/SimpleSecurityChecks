package com.khasmek.simplesecuritychecks.checker

import com.khasmek.simplesecuritychecks.model.CheckCategory
import com.khasmek.simplesecuritychecks.model.CheckItem
import com.khasmek.simplesecuritychecks.model.CheckResult
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

object RootChecker {

    fun getDefaultCategories(): List<CheckCategory> = listOf(
        CheckCategory(
            id = "su_binaries",
            name = "SU Binary Paths",
            description = "Checks for the existence of su binaries in common locations",
            items = listOf(
                CheckItem("/system/xbin/su"),
                CheckItem("/system/bin/su"),
                CheckItem("/sbin/su"),
                CheckItem("/system/su"),
                CheckItem("/system/bin/.ext/.su"),
                CheckItem("/data/local/xbin/su"),
                CheckItem("/data/local/bin/su"),
                CheckItem("/data/local/su"),
                CheckItem("/su/bin/su"),
            )
        ),
        CheckCategory(
            id = "root_apps",
            name = "Root Management Apps",
            description = "Checks for known root management app packages",
            items = listOf(
                CheckItem("com.topjohnwu.magisk"),
                CheckItem("eu.chainfire.supersu"),
                CheckItem("com.koushikdutta.superuser"),
                CheckItem("com.noshufou.android.su"),
                CheckItem("com.thirdparty.superuser"),
                CheckItem("com.yellowes.su"),
                CheckItem("com.kingroot.kinguser"),
                CheckItem("com.kingo.root"),
                CheckItem("me.phh.superuser"),
            )
        ),
        CheckCategory(
            id = "build_tags",
            name = "Build Tags",
            description = "Checks if the device build uses test-keys",
            items = listOf(
                CheckItem("test-keys"),
            )
        ),
        CheckCategory(
            id = "dangerous_props",
            name = "Dangerous System Props",
            description = "Checks for system properties that indicate root access",
            items = listOf(
                CheckItem("ro.debuggable=1"),
                CheckItem("ro.secure=0"),
                CheckItem("service.adb.root=1"),
                CheckItem("ro.adb.secure=0"),
            )
        ),
        CheckCategory(
            id = "rw_system",
            name = "RW /system Mount",
            description = "Checks if /system is mounted as read-write",
            items = listOf(
                CheckItem("/system mounted rw"),
            )
        ),
        CheckCategory(
            id = "su_command",
            name = "SU Command Execution",
            description = "Attempts to execute the su command",
            items = listOf(
                CheckItem("su -c id"),
            )
        ),
        CheckCategory(
            id = "busybox_paths",
            name = "Busybox Paths",
            description = "Checks for the existence of busybox binaries",
            items = listOf(
                CheckItem("/system/xbin/busybox"),
                CheckItem("/system/bin/busybox"),
                CheckItem("/sbin/busybox"),
                CheckItem("/su/bin/busybox"),
                CheckItem("/data/local/xbin/busybox"),
                CheckItem("/data/local/bin/busybox"),
            )
        ),
        CheckCategory(
            id = "magisk_artifacts",
            name = "Magisk Artifacts",
            description = "Checks for files and paths associated with Magisk",
            items = listOf(
                CheckItem("/sbin/.magisk"),
                CheckItem("/cache/.disable_magisk"),
                CheckItem("/dev/.magisk.unblock"),
                CheckItem("/data/adb/magisk"),
                CheckItem("/data/adb/magisk.db"),
                CheckItem("/data/adb/modules"),
                CheckItem("magisk in PATH"),
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
                "su_binaries" -> checkFileExists(label)
                "root_apps" -> checkPackageInstalled(label)
                "build_tags" -> checkBuildTags()
                "dangerous_props" -> checkSystemProp(label)
                "rw_system" -> checkRwSystem()
                "su_command" -> checkSuCommand()
                "busybox_paths" -> checkFileExists(label)
                "magisk_artifacts" -> {
                    if (label == "magisk in PATH") checkMagiskInPath()
                    else checkFileExists(label)
                }
                else -> CheckResult.ERROR
            }
        } catch (_: Exception) {
            CheckResult.ERROR
        }
    }

    private fun checkFileExists(path: String): CheckResult {
        return if (File(path).exists()) CheckResult.DETECTED else CheckResult.NOT_DETECTED
    }

    private fun checkPackageInstalled(packageName: String): CheckResult {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("pm", "list", "packages", packageName))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            reader.close()
            process.waitFor()
            if (output.contains("package:$packageName")) CheckResult.DETECTED else CheckResult.NOT_DETECTED
        } catch (_: Exception) {
            CheckResult.ERROR
        }
    }

    private fun checkBuildTags(): CheckResult {
        val tags = android.os.Build.TAGS
        return if (tags != null && tags.contains("test-keys")) CheckResult.DETECTED else CheckResult.NOT_DETECTED
    }

    private fun checkSystemProp(label: String): CheckResult {
        return try {
            val parts = label.split("=", limit = 2)
            if (parts.size != 2) return CheckResult.ERROR
            val key = parts[0]
            val expectedValue = parts[1]
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readText().trim()
            reader.close()
            process.waitFor()
            if (value == expectedValue) CheckResult.DETECTED else CheckResult.NOT_DETECTED
        } catch (_: Exception) {
            CheckResult.ERROR
        }
    }

    private fun checkRwSystem(): CheckResult {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("mount"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            reader.close()
            process.waitFor()
            val systemLine = output.lineSequence().find { line ->
                line.contains(" /system ") || line.contains(" on /system ")
            }
            if (systemLine != null && systemLine.contains("rw")) CheckResult.DETECTED else CheckResult.NOT_DETECTED
        } catch (_: Exception) {
            CheckResult.ERROR
        }
    }

    private fun checkSuCommand(): CheckResult {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText().trim()
            reader.close()
            val exitCode = process.waitFor()
            if (exitCode == 0 && output.contains("uid=")) CheckResult.DETECTED else CheckResult.NOT_DETECTED
        } catch (_: Exception) {
            CheckResult.NOT_DETECTED
        }
    }

    private fun checkMagiskInPath(): CheckResult {
        return try {
            val pathEnv = System.getenv("PATH") ?: return CheckResult.NOT_DETECTED
            val dirs = pathEnv.split(":")
            for (dir in dirs) {
                if (File(dir, "magisk").exists()) return CheckResult.DETECTED
            }
            CheckResult.NOT_DETECTED
        } catch (_: Exception) {
            CheckResult.ERROR
        }
    }
}
