package no.nordicsemi.android.nrftoolbox.security

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * Severity levels for vulnerabilities
 */
enum class VulnerabilitySeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

/**
 * Types of vulnerabilities we can detect
 */
enum class VulnerabilityType {
    INFORMATION_LEAKAGE,
    STATIC_MAC_ADDRESS,
    WEAK_PAIRING,
    GATT_EXPOSURE,
    INSECURE_OTA,
    DOS_VULNERABILITY
}

/**
 * MAC address types according to BLE spec
 */
enum class MacAddressType {
    PUBLIC,                  // Globally unique, trackable
    STATIC_RANDOM,          // Static random, trackable
    RANDOM_RESOLVABLE,      // Rotates, privacy-preserving
    RANDOM_NON_RESOLVABLE,  // Rotates, non-trackable
    UNKNOWN                 // Cannot determine
}

/**
 * Risk assessment levels
 */
enum class RiskLevel {
    LOW,
    MEDIUM,
    HIGH
}

/**
 * Represents a single vulnerability found in a device
 */
@Parcelize
data class Vulnerability(
    val type: VulnerabilityType,
    val severity: VulnerabilitySeverity,
    val title: String,
    val description: String,
    val evidence: String,
    val recommendation: String,
    val detectedAt: Long = System.currentTimeMillis()
) : Parcelable

/**
 * MAC address observation for tracking analysis
 */
@Parcelize
data class MacObservation(
    val macAddress: String,
    val timestamp: Long,
    val macType: MacAddressType
) : Parcelable

/**
 * RSSI (Signal Strength) observation for proximity tracking
 */
@Parcelize
data class RssiObservation(
    val rssi: Int,
    val timestamp: Long,
    val estimatedDistance: Double
) : Parcelable

/**
 * Manufacturer-specific data observation
 */
@Parcelize
data class ManufacturerDataObservation(
    val companyId: Int,
    val data: ByteArray,
    val timestamp: Long
) : Parcelable {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ManufacturerDataObservation
        if (companyId != other.companyId) return false
        if (!data.contentEquals(other.data)) return false
        if (timestamp != other.timestamp) return false
        return true
    }

    override fun hashCode(): Int {
        var result = companyId
        result = 31 * result + data.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }
}

/**
 * Advertising data observation (raw BLE advertising payload)
 */
@Parcelize
data class AdvertisingDataObservation(
    val data: ByteArray,
    val timestamp: Long
) : Parcelable {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as AdvertisingDataObservation
        if (!data.contentEquals(other.data)) return false
        if (timestamp != other.timestamp) return false
        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }
}

/**
 * Device security data - stores all collected information about a device
 */
@Parcelize
data class DeviceSecurityData(
    val address: String,
    var name: String? = null,
    var firstSeen: Long = System.currentTimeMillis(),
    var lastSeen: Long = System.currentTimeMillis(),
    val macObservations: MutableList<MacObservation> = mutableListOf(),
    val rssiHistory: MutableList<RssiObservation> = mutableListOf(),
    val manufacturerDataHistory: MutableList<ManufacturerDataObservation> = mutableListOf(),
    val advertisingDataHistory: MutableList<AdvertisingDataObservation> = mutableListOf(),
    var report: SecurityReport? = null
) : Parcelable

/**
 * Complete security report for a device
 */
@Parcelize
data class SecurityReport(
    val deviceAddress: String,
    val deviceName: String?,
    val vulnerabilities: List<Vulnerability>,
    val riskLevel: RiskLevel,
    val scanDuration: Long,
    val timestamp: Long = System.currentTimeMillis()
) : Parcelable {
    companion object {
        fun calculateRiskLevel(vulnerabilities: List<Vulnerability>): RiskLevel {
            if (vulnerabilities.isEmpty()) return RiskLevel.LOW

            val hasCritical = vulnerabilities.any { it.severity == VulnerabilitySeverity.CRITICAL }
            val hasHigh = vulnerabilities.any { it.severity == VulnerabilitySeverity.HIGH }
            val highCount = vulnerabilities.count {
                it.severity == VulnerabilitySeverity.HIGH ||
                        it.severity == VulnerabilitySeverity.CRITICAL
            }

            return when {
                hasCritical || highCount >= 2 -> RiskLevel.HIGH
                hasHigh || vulnerabilities.size >= 2 -> RiskLevel.MEDIUM
                else -> RiskLevel.LOW
            }
        }
    }
}

/**
 * Scan statistics summary
 */
data class ScanStats(
    val totalDevices: Int,
    val highRiskDevices: Int,
    val mediumRiskDevices: Int,
    val lowRiskDevices: Int
)

/**
 * Deep Scan Analysis Results
 */
data class DeepScanAnalysis(
    val manufacturerDataFindings: List<String>,
    val advertisingDataChanges: List<String>,
    val rssiPattern: RssiPattern,
    val movementDetected: Boolean,
    val additionalVulnerabilities: List<Vulnerability>
)

/**
 * RSSI pattern types for movement detection
 */
enum class RssiPattern {
    STABLE,           // Device is stationary
    PERIODIC,         // Device is rotating/moving periodically
    RANDOM,           // Random variation (normal)
    INCREASING,       // Device getting closer
    DECREASING        // Device moving away
}

/**
 * Company ID to Name mapping for common BLE manufacturers
 */
object ManufacturerCompanies {
    private val companies = mapOf(
        0x004C to "Apple Inc.",
        0x0006 to "Microsoft",
        0x00E0 to "Google",
        0x0075 to "Samsung Electronics",
        0x0157 to "Eufy (Anker Innovations)",
        0x0087 to "Garmin",
        0x0099 to "Xiaomi",
        0x02E5 to "Tile Inc.",
        0x0059 to "Nordic Semiconductor",
        0x0131 to "Fitbit"
    )

    fun getName(companyId: Int): String {
        return companies[companyId] ?: "Unknown (0x${companyId.toString(16).uppercase().padStart(4, '0')})"
    }
}

/**
 * Helper to calculate distance from RSSI
 * Uses the Free Space Path Loss formula
 */
object RssiCalculator {
    // TX power at 1 meter (typical for BLE devices)
    private const val TX_POWER_AT_1M = -59

    // Path loss exponent (2.0 for free space, 2.7-4.3 for indoor environments)
    private const val PATH_LOSS_EXPONENT = 2.5

    fun estimateDistance(rssi: Int): Double {
        if (rssi == 0) return -1.0

        val ratio = (TX_POWER_AT_1M - rssi) / (10.0 * PATH_LOSS_EXPONENT)
        return Math.pow(10.0, ratio)
    }

    fun getProximityLabel(distance: Double): String {
        return when {
            distance < 0 -> "Unknown"
            distance < 1.0 -> "Very Close"
            distance < 3.0 -> "Near"
            distance < 10.0 -> "Far"
            else -> "Very Far"
        }
    }
}