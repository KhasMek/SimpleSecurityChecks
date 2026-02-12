package com.khasmek.simplesecuritychecks.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.khasmek.simplesecuritychecks.checker.RootChecker
import com.khasmek.simplesecuritychecks.model.CheckResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun RootCheckScreen(modifier: Modifier = Modifier) {
    val categories = remember { mutableStateListOf(*RootChecker.getDefaultCategories().toTypedArray()) }
    var isChecking by remember { mutableStateOf(false) }
    var hasChecked by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    val rootDetected = hasChecked && categories.any { category ->
        category.items.any { it.result == CheckResult.DETECTED }
    }

    Column(modifier = modifier.fillMaxSize()) {
        // Verdict banner
        if (hasChecked && !isChecking) {
            Surface(
                color = if (rootDetected) Color(0xFFD32F2F) else Color(0xFF388E3C),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = if (rootDetected) "ROOTED" else "NOT ROOTED",
                    color = Color.White,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(16.dp)
                )
            }
        }

        // Select All / Deselect All + Copy Failed
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            CopyFailedButton(
                categories = categories,
                hasChecked = hasChecked,
                detectedIsSuccess = false
            )
            val allEnabled = categories.all { cat -> cat.items.all { it.enabled } }
            TextButton(onClick = {
                val newEnabled = !allEnabled
                for (i in categories.indices) {
                    categories[i] = categories[i].copy(
                        items = categories[i].items.map { it.copy(enabled = newEnabled) }
                    )
                }
            }) {
                Text(if (allEnabled) "Deselect All" else "Select All")
            }
        }

        // Category list
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            itemsIndexed(categories, key = { _, cat -> cat.id }) { catIndex, category ->
                CategoryCard(
                    category = category,
                    onToggleExpanded = {
                        categories[catIndex] = category.copy(expanded = !category.expanded)
                    },
                    onToggleCategoryEnabled = {
                        val allItemsEnabled = category.items.all { it.enabled }
                        val newEnabled = !allItemsEnabled
                        categories[catIndex] = category.copy(
                            items = category.items.map { it.copy(enabled = newEnabled) }
                        )
                    },
                    onToggleItemEnabled = { itemIndex ->
                        val updatedItems = category.items.toMutableList()
                        val item = updatedItems[itemIndex]
                        updatedItems[itemIndex] = item.copy(enabled = !item.enabled)
                        categories[catIndex] = category.copy(items = updatedItems)
                    }
                )
            }
        }

        // Check button
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            contentAlignment = Alignment.Center
        ) {
            if (isChecking) {
                CircularProgressIndicator()
            } else {
                Button(
                    onClick = {
                        isChecking = true
                        scope.launch {
                            val results = withContext(Dispatchers.IO) {
                                RootChecker.runChecks(categories.toList())
                            }
                            for (i in results.indices) {
                                categories[i] = results[i]
                            }
                            hasChecked = true
                            isChecking = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Check Root Status")
                }
            }
        }
    }
}
