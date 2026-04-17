/*
 * Copyright © 2017-2026 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import com.wireguard.android.Application
import com.wireguard.android.backend.Tunnel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicLong

/**
 * Manager for handling automatic tunnel connections based on network rules.
 */
object AutoConnectManager {
    private const val TAG = "WireGuard/AutoConnect"
    private val mutex = Mutex()
    private val lastCheckTime = AtomicLong(0)
    
    private var lastNetworkState: NetworkState? = null
    private data class NetworkState(val isWifi: Boolean, val isMobile: Boolean, val ssid: String?)

    fun start(context: Context) {
        Log.i(TAG, "Initializing AutoConnectManager")
        lastNetworkState = null
        updateMonitoringState(context)
    }

    fun updateMonitoringState(context: Context) {
        Application.getCoroutineScope().launch(Dispatchers.IO) {
            val tunnelManager = Application.getTunnelManager()
            val allTunnels = try {
                withTimeoutOrNull(3000) { tunnelManager.getTunnels() } ?: emptyList()
            } catch (e: Exception) {
                emptyList()
            }

            val configs = allTunnels.map { tunnel ->
                async { tunnel.getConfigAsync() }
            }.awaitAll()
            
            val needsMonitoring = configs.any { it.`interface`.isAutoConnectEnabled }
            
            Log.i(TAG, "Auto-connect monitoring needs: $needsMonitoring")

            val intent = Intent(context, AutoConnectService::class.java)
            if (needsMonitoring) {
                try {
                    lastNetworkState = null // Force re-eval on start/update
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(intent)
                    } else {
                        context.startService(intent)
                    }
                    checkAutoConnect(context)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start AutoConnectService", e)
                }
            } else {
                context.stopService(intent)
            }
        }
    }

    fun checkAutoConnect(context: Context) {
        val now = System.currentTimeMillis()
        val last = lastCheckTime.get()
        if (now - last < 2000) return // Throttle checks to every 2 seconds
        
        Application.getCoroutineScope().launch(Dispatchers.IO) {
            if (!mutex.tryLock()) return@launch
            try {
                lastCheckTime.set(System.currentTimeMillis())
                executeCheck(context)
            } finally {
                mutex.unlock()
            }
        }
    }

    private suspend fun executeCheck(context: Context) = withContext(Dispatchers.IO) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = cm.activeNetwork
            val caps = activeNetwork?.let { cm.getNetworkCapabilities(it) }

            val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            val isMobile = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
            val currentSsid = if (isWifi) getSsid(context, caps!!) else null
            
            val currentState = NetworkState(isWifi, isMobile, currentSsid)
            
            if (currentState == lastNetworkState) {
                return@withContext
            }
            lastNetworkState = currentState
            
            Log.i(TAG, "Network state changed: Wifi=$isWifi, Ssid=$currentSsid, Mobile=$isMobile. Executing full check.")

            val tunnelManager = Application.getTunnelManager()
            
            val allTunnels = withTimeoutOrNull(3000) { tunnelManager.getTunnels() } ?: return@withContext
            
            val tunnelConfigs = allTunnels.map { tunnel ->
                async { tunnel to tunnel.getConfigAsync() }
            }.awaitAll()

            val autoConnectTunnels = tunnelConfigs.filter { (_, config) ->
                config.`interface`.isAutoConnectEnabled
            }

            if (autoConnectTunnels.isEmpty()) {
                return@withContext
            }

            if (VpnService.prepare(context) != null) {
                Log.w(TAG, "VPN not authorized, skipping auto-connect")
                return@withContext
            }

            for ((tunnel, config) in autoConnectTunnels) {
                val inter = config.`interface`
                var targetState = Tunnel.State.DOWN

                if (isWifi) {
                    if (inter.isUseExcludeList) {
                        if (currentSsid == null || !inter.excludedWifi.contains(currentSsid)) {
                            targetState = Tunnel.State.UP
                        }
                    } else if (currentSsid != null && inter.includedWifi.contains(currentSsid)) {
                        targetState = Tunnel.State.UP
                    }
                } else if (isMobile && inter.autoConnectMobile) {
                    targetState = Tunnel.State.UP
                }

                if (targetState != tunnel.state) {
                    Log.i(TAG, "Auto-switch ${tunnel.name}: ${tunnel.state} -> $targetState")
                    runCatching { tunnelManager.setTunnelState(tunnel, targetState) }
                        .onFailure { Log.e(TAG, "Failed to switch ${tunnel.name}", it) }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Detailed check failed", e)
        }
    }

    private fun getSsid(context: Context, caps: NetworkCapabilities): String? {
        if (ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "Missing location permission for SSID detection")
            return null
        }

        try {
            var ssid: String? = null

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val wifiInfo = caps.transportInfo as? WifiInfo
                ssid = wifiInfo?.ssid?.removeSurrounding("\"")
            }

            if (ssid.isInvalidSsid()) {
                val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                @Suppress("DEPRECATION")
                val wifiInfo = wifiManager.connectionInfo
                ssid = wifiInfo?.ssid?.removeSurrounding("\"")
            }
            
            if (ssid.isInvalidSsid()) {
                val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                @Suppress("DEPRECATION")
                val info = connectivityManager.activeNetworkInfo
                if (info != null && info.type == ConnectivityManager.TYPE_WIFI) {
                    ssid = info.extraInfo?.removeSurrounding("\"")
                }
            }

            return if (ssid.isInvalidSsid()) null else ssid
        } catch (e: Exception) {
            Log.e(TAG, "SSID detection error", e)
            return null
        }
    }

    private fun String?.isInvalidSsid(): Boolean {
        return this.isNullOrEmpty() || this == WifiManager.UNKNOWN_SSID || this == "<unknown ssid>" || this == "0x"
    }
}
