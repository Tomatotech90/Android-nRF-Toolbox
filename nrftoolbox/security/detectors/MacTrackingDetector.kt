package no.nordicsemi.android.nrftoolbox.security.detectors

import no.nordicsemi.android.nrftoolbox.security.DeviceSecurityData
import no.nordicsemi.android.nrftoolbox.security.MacAddressType
import no.nordicsemi.android.nrftoolbox.security.MacObservation
import no.nordicsemi.android.nrftoolbox.security.Vulnerability
import no.nordicsemi.android.nrftoolbox.security.VulnerabilityDetector
import no.nordicsemi.android.nrftoolbox.security.VulnerabilitySeverity
import no.nordicsemi.android.nrftoolbox.security.VulnerabilityType

class MacTrackingDetector : VulnerabilityDetector {

    override val detectorId: String = "mac-tracking-detector"
    override val detectorName: String = "MAC Address Tracking Detector"

    companion object {
        const val MIN_OBSERVATIONS = 5
        const val PUBLIC_MAC_THRESHOLD = 60 * 1000L           // 60 seconds (for demo)
        const val STATIC_RANDOM_THRESHOLD = 60 * 1000L        // 60 seconds (for demo)
        const val RANDOM_PRIVATE_THRESHOLD = 2 * 60 * 1000L   // 2 minutes (for demo)
    }

    override fun analyze(scanResult: Any, deviceData: DeviceSecurityData): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()

        if (deviceData.macObservations.size < MIN_OBSERVATIONS) {
            return vulnerabilities
        }

        val macAddress = deviceData.address
        val macType = classifyMacAddress(macAddress)
        val observationDuration = deviceData.lastSeen - deviceData.firstSeen
        val hasRotated = checkMacRotation(deviceData.macObservations)

        if (!hasRotated) {
            when (macType) {
                MacAddressType.PUBLIC -> {
                    if (observationDuration >= PUBLIC_MAC_THRESHOLD) {
                        vulnerabilities.add(
                            createTrackingVulnerability(
                                macAddress, macType, observationDuration,
                                VulnerabilitySeverity.HIGH, deviceData.macObservations.size
                            )
                        )
                    }
                }
                MacAddressType.STATIC_RANDOM -> {
                    if (observationDuration >= STATIC_RANDOM_THRESHOLD) {
                        vulnerabilities.add(
                            createTrackingVulnerability(
                                macAddress, macType, observationDuration,
                                VulnerabilitySeverity.MEDIUM, deviceData.macObservations.size
                            )
                        )
                    }
                }
                else -> {}
            }
        }

        return vulnerabilities
    }

    fun classifyMacAddress(macAddress: String): MacAddressType {
        val bytes = macAddress.split(":").mapNotNull { it.toIntOrNull(16) }
        if (bytes.size != 6) return MacAddressType.UNKNOWN

        val firstByte = bytes[0]
        val lastByte = bytes[5]

        val bit0 = firstByte and 0x01
        val bit1 = firstByte and 0x02
        val bit46 = (lastByte shr 6) and 0x01
        val bit47 = (lastByte shr 7) and 0x01

        return when {
            bit0 == 0 && bit1 == 0 -> MacAddressType.PUBLIC
            bit46 == 1 && bit47 == 1 -> MacAddressType.STATIC_RANDOM
            bit46 == 1 && bit47 == 0 -> MacAddressType.RANDOM_RESOLVABLE
            bit46 == 0 && bit47 == 0 -> MacAddressType.RANDOM_NON_RESOLVABLE
            else -> MacAddressType.UNKNOWN
        }
    }

    fun checkMacRotation(observations: List<MacObservation>): Boolean {
        if (observations.size < 2) return false
        val uniqueMacs = observations.map { it.macAddress }.distinct()
        return uniqueMacs.size > 1
    }

    fun createTrackingVulnerability(
        macAddress: String,
        macType: MacAddressType,
        duration: Long,
        severity: VulnerabilitySeverity,
        observations: Int
    ): Vulnerability {
        val durationSeconds = duration / 1000

        return Vulnerability(
            type = VulnerabilityType.STATIC_MAC_ADDRESS,
            severity = severity,
            title = "Static MAC Address Enables Tracking",
            description = "Device uses a static MAC that hasn't rotated, enabling location tracking.",
            evidence = "MAC: $macAddress (${macType.name})\nObserved: $observations times over $durationSeconds seconds\nNo rotation detected",
            recommendation = "Enable MAC address rotation per BLE Privacy Specification (rotate every 15-60 minutes)."
        )
    }

    fun checkMacAddress(macAddress: String, deviceData: DeviceSecurityData): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()
        val currentTime = System.currentTimeMillis()

        val macType = classifyMacAddress(macAddress)

        deviceData.macObservations.add(
            MacObservation(macAddress, currentTime, macType)
        )

        if (deviceData.macObservations.size < MIN_OBSERVATIONS) {
            return vulnerabilities
        }

        val firstObservation = deviceData.macObservations.first()
        val observationDuration = currentTime - firstObservation.timestamp
        val hasRotated = checkMacRotation(deviceData.macObservations)

        if (!hasRotated) {
            val vulnerability = when (macType) {
                MacAddressType.PUBLIC -> {
                    if (observationDuration >= PUBLIC_MAC_THRESHOLD) {
                        createTrackingVulnerability(
                            macAddress, macType, observationDuration,
                            VulnerabilitySeverity.HIGH, deviceData.macObservations.size
                        )
                    } else null
                }
                MacAddressType.STATIC_RANDOM -> {
                    if (observationDuration >= STATIC_RANDOM_THRESHOLD) {
                        createTrackingVulnerability(
                            macAddress, macType, observationDuration,
                            VulnerabilitySeverity.MEDIUM, deviceData.macObservations.size
                        )
                    } else null
                }
                else -> null
            }
            vulnerability?.let { vulnerabilities.add(it) }
        }

        return vulnerabilities
    }

    override fun reset() {}
}