package com.khasmek.simplesecuritychecks.model

enum class CheckResult { DETECTED, NOT_DETECTED, ERROR }

data class CheckItem(
    val label: String,
    val enabled: Boolean = true,
    val result: CheckResult? = null,
    val detail: String? = null
)

data class CheckCategory(
    val id: String,
    val name: String,
    val description: String,
    val items: List<CheckItem>,
    val expanded: Boolean = false
)
