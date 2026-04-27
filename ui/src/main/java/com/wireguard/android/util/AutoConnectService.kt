/*
 * Copyright © 2017-2026 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.wireguard.android.R

class AutoConnectService : Service() {
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            // Network actually changed → force re-read of SSID.
            // We don't have caps here yet; the manager will fetch them.
            AutoConnectManager.checkAutoConnect(this@AutoConnectService, force = true)
        }

        override fun onLost(network: Network) {
            // Network lost → force re-evaluate (cached SSID will be cleared).
            AutoConnectManager.checkAutoConnect(this@AutoConnectService, force = true)
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            // Signal/property change on the same network.
            // Pass caps so the manager can read WifiInfo from the callback object
            // WITHOUT issuing any extra location-API call.
            // force=false → cached SSID is reused if the transport hasn't changed.
            AutoConnectManager.checkAutoConnect(
                this@AutoConnectService,
                force = false,
                caps = caps
            )
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Service creating")
        createNotificationChannel()
        
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.auto_connect_service_title))
            .setContentText(getString(R.string.auto_connect_service_desc))
            .setSmallIcon(R.drawable.ic_tile)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setSilent(true)
            .build()

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start foreground service", e)

        }

        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                cm.registerDefaultNetworkCallback(networkCallback)
            } else {
                val request = NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build()
                cm.registerNetworkCallback(request, networkCallback)
            }
        }.onFailure { Log.e(TAG, "Failed to register network callback", it) }
    }

    override fun onDestroy() {
        Log.i(TAG, "Service destroying")
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.unregisterNetworkCallback(networkCallback)
        }
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        AutoConnectManager.checkAutoConnect(this)
        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.auto_connect_service_title),
                NotificationManager.IMPORTANCE_MIN
            )
            channel.description = getString(R.string.auto_connect_service_desc)
            channel.setShowBadge(false)
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val TAG = "WireGuard/AutoConnectService"
        private const val CHANNEL_ID = "AutoConnectChannel"
        private const val NOTIFICATION_ID = 1002
    }
}
