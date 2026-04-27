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
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
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

    /**
     * Cached SSID from the last time the network actually became available.
     * Reused on onCapabilitiesChanged events to avoid redundant location reads.
     */
    @Volatile private var cachedSsid: String? = null

    private var autoConnectTunnelsCache: List<Pair<ObservableTunnel, Config>> = emptyList()

    fun start(context: Context) {
        Log.i(TAG, "Initializing AutoConnectManager")
        lastNetworkState = null
        cachedSsid = null
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

            val tunnelConfigs = allTunnels.map { tunnel ->
                async { tunnel to tunnel.getConfigAsync() }
            }.awaitAll()

            autoConnectTunnelsCache = tunnelConfigs.filter { (_, config) ->
                config.`interface`.isAutoConnectEnabled
            }

            val needsMonitoring = autoConnectTunnelsCache.isNotEmpty()

            Log.i(TAG, "Auto-connect monitoring needs: $needsMonitoring")

            val intent = Intent(context, AutoConnectService::class.java)
            if (needsMonitoring) {
                try {
                    lastNetworkState = null // Force re-eval on start/update
                    cachedSsid = null
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(intent)
                    } else {
                        context.startService(intent)
                    }
                    checkAutoConnect(context, force = true)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start AutoConnectService", e)
                }
            } else {
                context.stopService(intent)
            }
        }
    }

    /**
     * Triggers an auto-connect evaluation.
     *
     * @param force  When true the network has actually changed (onAvailable / onLost):
     *               re-read the SSID from the system.
     *               When false (onCapabilitiesChanged) reuse the cached SSID to avoid
     *               unnecessary location-API calls.
     * @param caps   Current NetworkCapabilities supplied by the network callback.
     *               When provided (force=true path) we read WifiInfo directly from it.
     */
    fun checkAutoConnect(
        context: Context,
        force: Boolean = false,
        caps: NetworkCapabilities? = null
    ) {
        Application.getCoroutineScope().launch(Dispatchers.IO) {
            if (!mutex.tryLock()) return@launch
            try {
                executeCheck(context, force, caps)
            } finally {
                mutex.unlock()
            }
        }
    }

    private suspend fun executeCheck(
        context: Context,
        force: Boolean,
        callbackCaps: NetworkCapabilities?
    ) = withContext(Dispatchers.IO) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = cm.activeNetwork
            val caps = callbackCaps ?: activeNetwork?.let { cm.getNetworkCapabilities(it) }

            val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            val isMobile = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true

            // --- Throttle / early-exit check BEFORE any location read ---
            // On a non-forced event (onCapabilitiesChanged) and same transport type,
            // skip immediately without touching any location API.
            val previousState = lastNetworkState
            val now = System.currentTimeMillis()
            val last = lastCheckTime.get()
            if (!force
                && previousState != null
                && previousState.isWifi == isWifi
                && previousState.isMobile == isMobile
                && now - last < 2000
            ) {
                return@withContext
            }

            // --- SSID resolution ---
            // Only read the SSID when the network actually switched to/from Wi-Fi
            // (force=true) or when we have no cached value yet.
            // onCapabilitiesChanged fires constantly for signal-strength updates;
            // we reuse the cached value to avoid OS-visible location-API accesses.
            val currentSsid: String? = when {
                !isWifi -> {
                    cachedSsid = null
                    null
                }
                force || cachedSsid == null -> {
                    val ssid = readSsid(context, caps)
                    cachedSsid = ssid
                    ssid
                }
                else -> cachedSsid // capability change on same Wi-Fi network → reuse
            }

            val currentState = NetworkState(isWifi, isMobile, currentSsid)
            if (!force && currentState == previousState) return@withContext

            lastNetworkState = currentState
            lastCheckTime.set(now)

            Log.i(TAG, "Evaluating auto-connect: Wifi=$isWifi, Ssid=$currentSsid, Mobile=$isMobile")

            val autoConnectTunnels = autoConnectTunnelsCache
            if (autoConnectTunnels.isEmpty()) return@withContext

            if (VpnService.prepare(context) != null) {
                Log.w(TAG, "VPN not authorized, skipping auto-connect")
                return@withContext
            }

            for ((tunnel, config) in autoConnectTunnels) {
                val inter = config.`interface`
                var targetState = Tunnel.State.DOWN

                if (isWifi && currentSsid != null) {
                    if (inter.isUseExcludeList) {
                        if (!inter.excludedWifi.contains(currentSsid)) {
                            targetState = Tunnel.State.UP
                        }
                    } else if (inter.includedWifi.contains(currentSsid)) {
                        targetState = Tunnel.State.UP
                    }
                } else if (isMobile && inter.autoConnectMobile) {
                    targetState = Tunnel.State.UP
                }

                if (targetState != tunnel.state) {
                    Log.i(TAG, "Auto-switch ${tunnel.name}: ${tunnel.state} -> $targetState")
                    runCatching { Application.getTunnelManager().setTunnelState(tunnel, targetState) }
                        .onFailure { Log.e(TAG, "Failed to switch ${tunnel.name}", it) }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Detailed check failed", e)
        }
    }

    /**
     * Reads the current Wi-Fi SSID with minimal location-API surface.
     *
     * On Android Q+ we use [WifiInfo] embedded in [NetworkCapabilities.getTransportInfo].
     * This is the only privacy-safe path: the OS supplies the info as part of an active
     * network callback, so it does NOT appear as a separate entry in the system's
     * "Recent location access" log.
     *
     * On Android < Q we must fall back to the deprecated [WifiManager.getConnectionInfo],
     * but that only happens on old devices and only when the network actually changes
     * (force=true path), not on every capability update.
     */
    private fun readSsid(context: Context, caps: NetworkCapabilities?): String? {
        if (ContextCompat.checkSelfPermission(
                context,
                android.Manifest.permission.ACCESS_FINE_LOCATION
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.w(TAG, "Missing location permission for SSID detection")
            return null
        }

        return try {
            // Primary path (Android Q+): WifiInfo embedded in NetworkCapabilities.
            // Does NOT trigger a visible location-access record.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && caps != null) {
                val ssid = (caps.transportInfo as? WifiInfo)
                    ?.ssid
                    ?.removeSurrounding("\"")
                if (!ssid.isInvalidSsid()) return ssid
            }

            // Legacy fallback (Android < Q only).
            // Triggers a location-access record but cannot be avoided on old APIs.
            @Suppress("DEPRECATION")
            val wifiManager =
                context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            val ssid = wifiManager.connectionInfo?.ssid?.removeSurrounding("\"")
            if (!ssid.isInvalidSsid()) ssid else null
        } catch (e: Exception) {
            Log.e(TAG, "SSID detection error", e)
            null
        }
    }

    private fun String?.isInvalidSsid(): Boolean =
        isNullOrEmpty() || this == WifiManager.UNKNOWN_SSID || this == "<unknown ssid>" || this == "0x"
}
