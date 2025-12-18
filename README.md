# BLE Security Mapper

A security analysis tool for Bluetooth Low Energy devices. Built as an extension to the nRF Toolbox Android application, this project adds passive vulnerability scanning capabilities to detect common BLE security issues.

## What This Does

BLE Security Mapper scans nearby Bluetooth devices and identifies potential security vulnerabilities without connecting to them. It's purely passive scanning—reading advertisement packets and analyzing device characteristics to flag known security risks.

The tool detects things like:
- Information leakage in device names (emails, serial numbers, owner names)
- Static MAC addresses that enable long-term tracking
- Printer-specific vulnerabilities based on documented CVEs
- Deprecated Bluetooth protocols
- Buffer overflow risks in device implementations

Each detected vulnerability includes severity ratings, technical evidence, and remediation recommendations.

## Project Structure

This is built on top of Nordic Semiconductor's [nRF Toolbox](https://github.com/NordicSemiconductor/Android-nRF-Toolbox). You'll need to fork their repository first. 
See their [README](https://github.com/NordicSemiconductor/Android-nRF-Toolbox/blob/main/README.md) for base application details.

The following directory structure will be added to the forked repository:

```
app/src/main/java/no/nordicsemi/android/nrftoolbox/
└── security/                           # New module (all custom code)
    ├── Models.kt                       # Data models and enums
    ├── VulnerabilityDetector.kt        # Detector interface
    ├── SecurityAnalyzer.kt             # Core analysis engine
    ├── detectors/                      # Detection modules
    │   ├── AdLeakDetector.kt          # Info leakage detection
    │   ├── MacTrackingDetector.kt     # MAC tracking detection
    │   ├── PrinterVulnerabilityDetector.kt
    │   └── DeviceProbeDetector.kt     # Protocol vulnerability detection
    └── view/
        └── SecurityMapperScreen.kt    # UI implementation
```

**What's Native vs Custom:**
- nRF Toolbox base app: Native (Nordic Semiconductor's open source code)
- Everything in `security/` folder: Custom implementation for this project

## File Breakdown

### Core Files

**Models.kt**
Defines all data structures. This includes the `Vulnerability` class, severity/type enums, device-tracking data, risk-level classifications, and UI display models. Basically, all the types the system works with.

**VulnerabilityDetector.kt**
An interface that all detector modules implement. Simple contract: take device data, return a list of vulnerabilities found. Keeps detectors modular and testable.

**SecurityAnalyzer.kt**
The main engine. Receives BLE scan results, maintains device history, runs all detectors, calculates risk levels, and exposes results via StateFlow for the UI. About 170 lines total.

Key responsibilities:
- Track devices across multiple scan results
- Build device profiles (RSSI history, manufacturer data, advertising patterns)
- Coordinate detector execution
- Calculate aggregate risk levels (HIGH/MEDIUM/LOW)
- Provide area safety summaries

### Detection Modules

**AdLeakDetector.kt**
Scans device names for information leakage. Uses regex patterns to catch emails, serial numbers (like `SN-123456`), owner names (possessives like "John's iPhone"), and location identifiers. Flags each as a separate vulnerability with appropriate severity.

**MacTrackingDetector.kt**
Analyzes MAC addresses to detect tracking risks. Checks whether the address is static (not randomized) by examining the locally administered bit. Also flags devices with high observation counts as potential surveillance equipment. Includes time-span calculations to show how long a device has been visible.

**PrinterVulnerabilityDetector.kt**
Identifies Bluetooth-enabled printers and flags known vulnerability classes. Detection is keyword-based (hp, canon, epson, printer, etc.). Reports two common printer issues: device information exposure and OBEX print job injection vulnerability. Based on documented CVEs from security research.

**DeviceProbeDetector.kt**
Detects devices using deprecated or vulnerable Bluetooth protocols. Checks for Classic Bluetooth (vulnerable to KNOB attack), looks for buffer overflow indicators in advertising data, and identifies devices accepting unauthenticated connections.

### UI Layer

**SecurityMapperScreen.kt**
Jetpack Compose UI. Shows real-time scan results with color-coded risk indicators (red/orange/green). Displays vulnerability details, device metrics (RSSI, observation count), and area safety summary. Includes a 90-second scanning mode with live updates.

Features:
- Expandable device cards showing full vulnerability details
- Area safety assessment (SAFE/CAUTION/WARNING/DANGER)
- Device statistics (total devices, high/medium/low risk counts)
- Empty state handling

## How It Works

1. **Scanning**: Uses Android's BluetoothLeScanner in low-latency mode
2. **Data Collection**: Extracts device name, MAC address, RSSI, manufacturer data, advertising flags
3. **Device Tracking**: Builds history over multiple scan results (RSSI changes, first/last seen times)
4. **Detection**: Each detector module analyzes the device independently
5. **Risk Calculation**: Aggregates vulnerabilities—any HIGH/CRITICAL severity = HIGH risk, 2+ vulnerabilities = MEDIUM risk
6. **Display**: UI updates reactively via Kotlin Flow

The analysis is entirely based on passive observation of broadcast packets. The scanner listens to advertising data and builds device profiles over time by correlating multiple observations.

## Technical Details

**Language**: Kotlin  
**UI Framework**: Jetpack Compose  
**Architecture**: MVVM-ish (StateFlow for reactive updates)  
**BLE API**: Android BluetoothLeScanner  
**Base Application**: nRF Toolbox for Android

**Dependencies** (added to nRF Toolbox):
- Kotlin Coroutines (for async scanning)
- Jetpack Compose (UI)
- Material3 (design components)

## Testing

For development/testing, you can broadcast a BLE device with vulnerable characteristics using Linux:

```bash
# Broadcast a device name containing identifiable information
sudo btmgmt -i hci0 name "admin@company.com-Floor3-HP-Printer"
sudo btmgmt -i hci0 advertising on
```

This broadcasts a device that triggers:
- Email in device name (CRITICAL)
- Owner name detection
- Location identifier
- Static MAC address
- Printer vulnerabilities

Expected result: HIGH risk classification with 5+ vulnerabilities detected.

## Build Instructions

1. Clone nRF Toolbox repository
2. Add the `security/` module to the project structure
3. Update navigation to include SecurityMapperScreen
4. Build with Android Studio (Gradle sync should handle dependencies)
5. Run on an Android device with BLE support

Requires Android 5.0+ (API 21) for BLE scanning, Android 12+ (API 31) for some features.
