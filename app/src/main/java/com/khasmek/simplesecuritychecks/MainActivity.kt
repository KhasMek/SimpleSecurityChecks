package com.khasmek.simplesecuritychecks

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.khasmek.simplesecuritychecks.ui.CryptoCheckScreen
import com.khasmek.simplesecuritychecks.ui.RootCheckScreen
import com.khasmek.simplesecuritychecks.ui.IntegrityCheckScreen
import com.khasmek.simplesecuritychecks.ui.SslPinningScreen
import com.khasmek.simplesecuritychecks.ui.theme.SimpleSecurityChecksTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SimpleSecurityChecksTheme {
                val navController = rememberNavController()
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route

                data class NavItem(val route: String, val label: String, val icon: ImageVector)

                val navItems = listOf(
                    NavItem("root_checks", "Root", Icons.Default.Build),
                    NavItem("crypto_ops", "Crypto", Icons.Default.Lock),
                    NavItem("ssl_pinning", "SSL Pin", Icons.Default.Security),
                    NavItem("integrity", "Integrity", Icons.Default.VerifiedUser),
                )

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    bottomBar = {
                        NavigationBar {
                            navItems.forEach { item ->
                                NavigationBarItem(
                                    icon = { Icon(item.icon, contentDescription = item.label) },
                                    label = { Text(item.label) },
                                    selected = currentRoute == item.route,
                                    onClick = {
                                        navController.navigate(item.route) {
                                            popUpTo(navController.graph.startDestinationId) {
                                                saveState = true
                                            }
                                            launchSingleTop = true
                                            restoreState = true
                                        }
                                    }
                                )
                            }
                        }
                    }
                ) { innerPadding ->
                    NavHost(
                        navController = navController,
                        startDestination = "root_checks",
                        modifier = Modifier.padding(innerPadding)
                    ) {
                        composable("root_checks") {
                            RootCheckScreen()
                        }
                        composable("crypto_ops") {
                            CryptoCheckScreen()
                        }
                        composable("ssl_pinning") {
                            SslPinningScreen()
                        }
                        composable("integrity") {
                            IntegrityCheckScreen()
                        }
                    }
                }
            }
        }
    }
}
