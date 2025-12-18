package no.nordicsemi.android.nrftoolbox.security.detectors

import no.nordicsemi.android.nrftoolbox.security.*

class AdLeakDetector : VulnerabilityDetector {

    override val detectorId: String = "ad-leak-detector"
    override val detectorName: String = "Advertisement Information Leakage Detector"

    private val serialPattern = Regex("[A-Z]{2,}[-_]?\\d{4,}")
    private val emailPattern = Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
    private val possessivePattern = Regex("\\w+'s\\s")

    private val commonBrands = setOf(
        "Apple", "Samsung", "Google", "Microsoft", "Amazon",
        "Fitbit", "Garmin", "Xiaomi", "Huawei", "OnePlus",
        "Sony", "LG", "Motorola", "Nokia", "Bluetooth",
        "BLE", "Smart", "Device", "Tracker", "Watch"
    )

    private val commonLongWords = setOf(
        "Bluetooth", "Wireless", "Controller", "Headphones",
        "Smartwatch", "Tracker", "Assistant", "Speaker"
    )

    override fun analyze(scanResult: Any, deviceData: DeviceSecurityData): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()
        val deviceName = deviceData.name ?: return vulnerabilities

        checkSerialNumber(deviceName)?.let { vulnerabilities.add(it) }
        checkEmail(deviceName)?.let { vulnerabilities.add(it) }
        checkPossessive(deviceName)?.let { vulnerabilities.add(it) }
        checkLongName(deviceName)?.let { vulnerabilities.add(it) }
        checkProperNouns(deviceName)?.let { vulnerabilities.add(it) }

        return vulnerabilities
    }

    fun checkSerialNumber(deviceName: String): Vulnerability? {
        val match = serialPattern.find(deviceName) ?: return null
        val serial = match.value

        if (commonBrands.any { serial.contains(it, ignoreCase = true) }) {
            return null
        }

        return Vulnerability(
            type = VulnerabilityType.INFORMATION_LEAKAGE,
            severity = VulnerabilitySeverity.HIGH,
            title = "Serial Number Exposed",
            description = "Device broadcasts what appears to be a serial number or unique identifier in its name.",
            evidence = "Found pattern: '$serial' in device name '$deviceName'",
            recommendation = "Remove serial numbers from the advertised device name. Use a generic name instead."
        )
    }

    fun checkEmail(deviceName: String): Vulnerability? {
        val match = emailPattern.find(deviceName) ?: return null
        val email = match.value

        return Vulnerability(
            type = VulnerabilityType.INFORMATION_LEAKAGE,
            severity = VulnerabilitySeverity.CRITICAL,
            title = "Email Address Exposed",
            description = "Device broadcasts an email address, directly identifying the owner.",
            evidence = "Found email: '$email' in device name '$deviceName'",
            recommendation = "Remove email addresses from device names immediately."
        )
    }

    fun checkPossessive(deviceName: String): Vulnerability? {
        val match = possessivePattern.find(deviceName) ?: return null

        return Vulnerability(
            type = VulnerabilityType.INFORMATION_LEAKAGE,
            severity = VulnerabilitySeverity.HIGH,
            title = "Owner Name Exposed",
            description = "Device name contains possessive form, likely revealing owner's name.",
            evidence = "Found possessive pattern in: '$deviceName'",
            recommendation = "Use generic device names without personal identifiers."
        )
    }

    fun checkLongName(deviceName: String): Vulnerability? {
        if (deviceName.length < 15) return null

        if (commonLongWords.any { deviceName.contains(it, ignoreCase = true) }) {
            return null
        }

        return Vulnerability(
            type = VulnerabilityType.INFORMATION_LEAKAGE,
            severity = VulnerabilitySeverity.MEDIUM,
            title = "Potentially Identifying Name",
            description = "Device uses a long, potentially identifying name.",
            evidence = "Device name is ${deviceName.length} characters: '$deviceName'",
            recommendation = "Shorten device name to a generic identifier."
        )
    }

    fun checkProperNouns(deviceName: String): Vulnerability? {
        val words = deviceName.split(Regex("\\s+"))
        val capitalizedWords = words.filter {
            it.isNotEmpty() && it[0].isUpperCase() && it.length > 1
        }.filter { word ->
            !commonBrands.contains(word)
        }

        if (capitalizedWords.size < 2) return null

        return Vulnerability(
            type = VulnerabilityType.INFORMATION_LEAKAGE,
            severity = VulnerabilitySeverity.MEDIUM,
            title = "Multiple Identifying Terms",
            description = "Device name contains multiple capitalized words.",
            evidence = "Found ${capitalizedWords.size} terms: ${capitalizedWords.joinToString(", ")}",
            recommendation = "Use a single generic term for device name."
        )
    }

    fun checkDeviceName(deviceName: String, address: String): List<Vulnerability> {
        val vulnerabilities = mutableListOf<Vulnerability>()

        checkSerialNumber(deviceName)?.let { vulnerabilities.add(it) }
        checkEmail(deviceName)?.let { vulnerabilities.add(it) }
        checkPossessive(deviceName)?.let { vulnerabilities.add(it) }
        checkLongName(deviceName)?.let { vulnerabilities.add(it) }
        checkProperNouns(deviceName)?.let { vulnerabilities.add(it) }

        return vulnerabilities
    }

    override fun reset() {}
}