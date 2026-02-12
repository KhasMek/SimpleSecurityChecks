package com.khasmek.simplesecuritychecks.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TriStateCheckbox
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.khasmek.simplesecuritychecks.model.CheckCategory
import com.khasmek.simplesecuritychecks.model.CheckResult

@Composable
internal fun CategoryCard(
    category: CheckCategory,
    onToggleExpanded: () -> Unit,
    onToggleCategoryEnabled: () -> Unit,
    onToggleItemEnabled: (Int) -> Unit,
    detectedIsSuccess: Boolean = false
) {
    val enabledCount = category.items.count { it.enabled }
    val toggleState = when (enabledCount) {
        0 -> ToggleableState.Off
        category.items.size -> ToggleableState.On
        else -> ToggleableState.Indeterminate
    }

    val detectedCount = category.items.count { it.result == CheckResult.DETECTED }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column {
            // Category header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onToggleExpanded() }
                    .padding(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TriStateCheckbox(
                    state = toggleState,
                    onClick = onToggleCategoryEnabled
                )
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = category.name,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        if (detectedCount > 0) {
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "$detectedCount found",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (detectedIsSuccess) Color(0xFF388E3C) else Color(0xFFD32F2F)
                            )
                        }
                    }
                    Text(
                        text = category.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Icon(
                    imageVector = if (category.expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = if (category.expanded) "Collapse" else "Expand"
                )
            }

            // Expanded item list
            AnimatedVisibility(visible = category.expanded) {
                Column(modifier = Modifier.padding(start = 16.dp, bottom = 8.dp)) {
                    category.items.forEachIndexed { itemIndex, item ->
                        Column {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onToggleItemEnabled(itemIndex) }
                                    .padding(vertical = 2.dp, horizontal = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Checkbox(
                                    checked = item.enabled,
                                    onCheckedChange = { onToggleItemEnabled(itemIndex) }
                                )
                                Text(
                                    text = item.label,
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.weight(1f)
                                )
                                if (item.result != null) {
                                    ResultIcon(item.result, detectedIsSuccess = detectedIsSuccess)
                                }
                            }
                            if (!item.detail.isNullOrEmpty()) {
                                Text(
                                    text = item.detail,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(start = 56.dp, end = 8.dp, bottom = 4.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

internal fun formatFailedFindings(
    categories: List<CheckCategory>,
    detectedIsSuccess: Boolean
): String {
    val failedResult = if (detectedIsSuccess) CheckResult.NOT_DETECTED else CheckResult.DETECTED
    return buildString {
        for (category in categories) {
            val failedItems = category.items.filter { item ->
                item.enabled && (item.result == failedResult || item.result == CheckResult.ERROR)
            }
            if (failedItems.isNotEmpty()) {
                appendLine("[${category.name}]")
                for (item in failedItems) {
                    appendLine("  - ${item.label} (${item.result})")
                    if (!item.detail.isNullOrEmpty()) {
                        appendLine("    ${item.detail}")
                    }
                }
                appendLine()
            }
        }
    }.trimEnd()
}

@Composable
internal fun CopyFailedButton(
    categories: List<CheckCategory>,
    hasChecked: Boolean,
    detectedIsSuccess: Boolean
) {
    if (!hasChecked) return
    val text = formatFailedFindings(categories, detectedIsSuccess)
    if (text.isEmpty()) return
    val context = LocalContext.current
    TextButton(onClick = {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Failed Findings", text))
    }) {
        Text("Copy Failed")
    }
}

@Composable
internal fun ResultIcon(result: CheckResult, detectedIsSuccess: Boolean = false) {
    when (result) {
        CheckResult.DETECTED -> Icon(
            imageVector = if (detectedIsSuccess) Icons.Default.Check else Icons.Default.Close,
            contentDescription = "Detected",
            tint = if (detectedIsSuccess) Color(0xFF388E3C) else Color(0xFFD32F2F),
            modifier = Modifier.size(20.dp)
        )
        CheckResult.NOT_DETECTED -> Icon(
            imageVector = if (detectedIsSuccess) Icons.Default.Close else Icons.Default.Check,
            contentDescription = "Not Detected",
            tint = if (detectedIsSuccess) Color(0xFFD32F2F) else Color(0xFF388E3C),
            modifier = Modifier.size(20.dp)
        )
        CheckResult.ERROR -> Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = "Error",
            tint = Color(0xFFF57C00),
            modifier = Modifier.size(20.dp)
        )
    }
}
