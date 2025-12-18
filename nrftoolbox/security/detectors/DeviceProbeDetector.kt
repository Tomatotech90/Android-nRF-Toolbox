package no.nordicsemi.android.nrftoolbox.security.detectors

import no.nordicsemi.android.nrftoolbox.security.*

/**
 * Advanced device analysis detector that identifies deprecated protocols,
 * buffer overflow risks, and service exposure patterns
 *
 * Analyzes devices for:
 * - Deprecated Bluetooth services with known vulnerabilities
 * - Abnormally long device names (potential buffer overflow targets)
 * - Service advertisement patterns indicating poor security implementation
 */
class DeviceProbeDetector : VulnerabilityDetector {

    override val detectorId: String = "device-probe-detector"
    override val detectorName: String = "Advanced Device Security Probe"

    companion object {
        // Deprecated/vulnerable service UUIDs
        private val DEPRECATED_SERVICES = mapOf(
            "00001105-0000-1000-8000-00805f9b34fb" to DeprecatedServiceInfo(
                "OBEX Object Push",
                "Historical buffer overflow vulnerabilities in OBEX parsers. Often implemented without authentication."
            ),
            "00001101-0000-1000-8000-00805f9b34fb" to DeprecatedServiceInfo(
                "Serial Port Profile (SPP)",
                "Legacy serial communication. Older implementations vulnerable to command injection and buffer overflows."
            ),
            "0000110a-0000-1000-8000-00805f9b34fb" to DeprecatedServiceInfo(
                "Audio Source",
                "Some implementations leak audio stream without proper pairing verification."
            )
        )

        // Threshold for suspiciously long device names
        const val SUSPICIOUS_NAME_LENGTH = 40

        // Very long names that might trigger buffer overflows
        const val BUFFER_OVERFLOW_NAME_LENGTH = 60
    }

    override fun analyze(scanResult: Any, deviceData: DeviceSecurityData): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()

        // Check for deprecated/vulnerable services
        // Note: In passive scanning, we rely on advertised service UUIDs
        // Full service enumeration would require active connection

        // Check device name length (potential buffer overflow indicator)
        deviceData.name?.let { name ->
            checkNameLength(name)?.let { vulnerabilities.add(it) }
        }

        // Check for excessive advertising data (potential overflow)
        if (deviceData.advertisingDataHistory.isNotEmpty()) {
            checkAdvertisingDataSize(deviceData)?.let { vulnerabilities.add(it) }
        }

        return vulnerabilities
    }

    /**
     * Analyzes device name length for buffer overflow risk
     */
    private fun checkNameLength(deviceName: String): Vulnerability? {
        val length = deviceName.length

        return when {
            length >= BUFFER_OVERFLOW_NAME_LENGTH -> {
                Vulnerability(
                    type = VulnerabilityType.DOS_VULNERABILITY,
                    severity = VulnerabilitySeverity.HIGH,
                    title = "Potential Buffer Overflow Risk - Excessive Name Length",
                    description = "Device broadcasts an unusually long name ($length characters). Devices with poor input validation may be vulnerable to buffer overflow attacks when processing this name. Historical Bluetooth vulnerabilities (BlueBorne, KNOB attack variants) have exploited name field parsing. Long names can also indicate misconfiguration or attempted exploitation.",
                    evidence = "Device name length: $length characters\nName: '${deviceName.take(50)}${if (length > 50) "..." else ""}'",
                    recommendation = "If this is your device: Shorten the device name to under 20 characters. If this is an unknown device: Avoid connecting - the long name may be crafted to exploit vulnerabilities in Bluetooth stack name parsing."
                )
            }
            length >= SUSPICIOUS_NAME_LENGTH -> {
                Vulnerability(
                    type = VulnerabilityType.INFORMATION_LEAKAGE,
                    severity = VulnerabilitySeverity.MEDIUM,
                    title = "Unusually Long Device Name",
                    description = "Device uses a long name ($length characters). While not necessarily vulnerable, this increases attack surface for name-based exploits and may indicate poor security hygiene. Recommended Bluetooth name length is 10-20 characters.",
                    evidence = "Device name length: $length characters",
                    recommendation = "Shorten device name to a concise identifier (10-20 characters). Remove any unnecessary information from the advertised name."
                )
            }
            else -> null
        }
    }

    /**
     * Checks advertising data size for anomalies
     */
    private fun checkAdvertisingDataSize(deviceData: DeviceSecurityData): Vulnerability? {
        val recentData = deviceData.advertisingDataHistory.lastOrNull() ?: return null
        val dataSize = recentData.data.size

        // BLE advertising packets have 31-byte limit (standard)
        // Extended advertising allows larger payloads but is less common
        if (dataSize > 31) {
            return Vulnerability(
                type = VulnerabilityType.DOS_VULNERABILITY,
                severity = VulnerabilitySeverity.MEDIUM,
                title = "Extended Advertising Data Detected",
                description = "Device uses extended advertising data ($dataSize bytes). While supported in Bluetooth 5.0+, this feature increases packet parsing complexity and has been associated with DoS vulnerabilities in some Bluetooth stack implementations. Larger advertising payloads provide more opportunities for malformed data injection.",
                evidence = "Advertising data size: $dataSize bytes (exceeds standard 31-byte limit)",
                recommendation = "Monitor device behavior. Extended advertising is legitimate for complex devices but may indicate aggressive advertising or potential exploit attempts."
            )
        }

        return null
    }

    /**
     * Analyzes deprecated services (would require service UUID extraction from advertising data)
     * This is a placeholder showing the intended analysis
     */
    private fun checkDeprecatedServices(serviceUuids: List<String>): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()

        serviceUuids.forEach { uuid ->
            DEPRECATED_SERVICES[uuid.lowercase()]?.let { serviceInfo ->
                vulnerabilities.add(
                    Vulnerability(
                        type = VulnerabilityType.WEAK_PAIRING,
                        severity = VulnerabilitySeverity.HIGH,
                        title = "Deprecated Service Advertised: ${serviceInfo.name}",
                        description = serviceInfo.vulnerabilityDescription,
                        evidence = "Service UUID: $uuid",
                        recommendation = "Avoid connecting to devices advertising deprecated services. If this is your device, disable legacy service support and use modern BLE GATT services instead."
                    )
                )
            }
        }

        return vulnerabilities
    }

    override fun reset() {
        // No state to reset
    }
}

/**
 * Information about deprecated/vulnerable Bluetooth services
 */
private data class DeprecatedServiceInfo(
    val name: String,
    val vulnerabilityDescription: String
)