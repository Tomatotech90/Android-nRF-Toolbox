package no.nordicsemi.android.nrftoolbox.security

import android.bluetooth.le.ScanResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import no.nordicsemi.android.nrftoolbox.security.detectors.*
import android.annotation.SuppressLint

/**
 * Central security analysis engine
 * Analyzes BLE devices and generates vulnerability reports
 */
class SecurityAnalyzer {

    // All registered detectors
    private val detectors: List<VulnerabilityDetector> = listOf(
        AdLeakDetector(),
        MacTrackingDetector(),
        PrinterVulnerabilityDetector(),
        DeviceProbeDetector()
    )

    // Device tracking
    private val deviceDataMap = mutableMapOf<String, DeviceSecurityData>()

    // Analysis results (for UI)
    private val _analysisResults = MutableStateFlow<Map<String, DeviceAnalysisResult>>(emptyMap())
    val analysisResults: StateFlow<Map<String, DeviceAnalysisResult>> = _analysisResults.asStateFlow()

    /**
     * Reset all data
     */
    fun reset() {
        deviceDataMap.clear()
        _analysisResults.value = emptyMap()
        detectors.forEach { it.reset() }
    }

    /**
     * Analyze a BLE scan result
     */
    @SuppressLint("MissingPermission")
    fun analyzeDevice(scanResult: ScanResult) {
        val address = scanResult.device.address
        val name = scanResult.device.name
        val rssi = scanResult.rssi

        // Get or create device data
        val deviceData = deviceDataMap.getOrPut(address) {
            DeviceSecurityData(
                address = address,
                name = name,
                firstSeen = System.currentTimeMillis()
            )
        }

        // Update data
        deviceData.lastSeen = System.currentTimeMillis()
        if (deviceData.name == null && name != null) {
            deviceData.name = name
        }

        // Record RSSI
        deviceData.rssiHistory.add(
            RssiObservation(
                rssi = rssi,
                timestamp = System.currentTimeMillis(),
                estimatedDistance = RssiCalculator.estimateDistance(rssi)
            )
        )

        // Extract manufacturer data
        val manufacturerData = scanResult.scanRecord?.manufacturerSpecificData?.let { sparse ->
            val map = mutableMapOf<Int, ByteArray>()
            for (i in 0 until sparse.size()) {
                map[sparse.keyAt(i)] = sparse.valueAt(i)
            }
            map
        }

        manufacturerData?.forEach { (companyId, data) ->
            deviceData.manufacturerDataHistory.add(
                ManufacturerDataObservation(
                    companyId = companyId,
                    data = data,
                    timestamp = System.currentTimeMillis()
                )
            )
        }

        // Record advertising data
        scanResult.scanRecord?.bytes?.let { bytes ->
            deviceData.advertisingDataHistory.add(
                AdvertisingDataObservation(
                    data = bytes,
                    timestamp = System.currentTimeMillis()
                )
            )
        }

        // Run all detectors
        val vulnerabilities = mutableListOf<Vulnerability>()
        detectors.forEach { detector ->
            vulnerabilities.addAll(detector.analyze(scanResult, deviceData))
        }

        // Calculate risk level
        val riskLevel = calculateRiskLevel(vulnerabilities)

        // Create analysis result
        val result = DeviceAnalysisResult(
            address = address,
            name = name,
            rssi = rssi,
            vulnerabilities = vulnerabilities,
            riskLevel = riskLevel,
            observationCount = deviceData.rssiHistory.size,
            firstSeen = deviceData.firstSeen,
            lastSeen = deviceData.lastSeen
        )

        // Update results
        val updated = _analysisResults.value.toMutableMap()
        updated[address] = result
        _analysisResults.value = updated
    }

    /**
     * Calculate overall risk level based on vulnerabilities
     */
    private fun calculateRiskLevel(vulnerabilities: List<Vulnerability>): RiskLevel {
        if (vulnerabilities.isEmpty()) return RiskLevel.LOW

        val hasHigh = vulnerabilities.any { it.severity == VulnerabilitySeverity.HIGH }
        val hasCritical = vulnerabilities.any { it.severity == VulnerabilitySeverity.CRITICAL }

        return when {
            hasCritical || hasHigh -> RiskLevel.HIGH
            vulnerabilities.size >= 2 -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
    }

    /**
     * Get area safety summary
     */
    fun getAreaSafetySummary(): AreaSafetySummary {
        val results = _analysisResults.value.values
        return AreaSafetySummary(
            totalDevices = results.size,
            highRiskDevices = results.count { it.riskLevel == RiskLevel.HIGH },
            mediumRiskDevices = results.count { it.riskLevel == RiskLevel.MEDIUM },
            lowRiskDevices = results.count { it.riskLevel == RiskLevel.LOW }
        )
    }
}

/**
 * Device analysis result (for UI display)
 */
data class DeviceAnalysisResult(
    val address: String,
    val name: String?,
    val rssi: Int,
    val vulnerabilities: List<Vulnerability>,
    val riskLevel: RiskLevel,
    val observationCount: Int,
    val firstSeen: Long,
    val lastSeen: Long
)

/**
 * Area safety summary
 */
data class AreaSafetySummary(
    val totalDevices: Int,
    val highRiskDevices: Int,
    val mediumRiskDevices: Int,
    val lowRiskDevices: Int
)
