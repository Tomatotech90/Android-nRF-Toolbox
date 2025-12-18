package no.nordicsemi.android.nrftoolbox.security.view

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import no.nordicsemi.android.nrftoolbox.security.*
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityMapperScreen(
    analyzer: SecurityAnalyzer = remember { SecurityAnalyzer() }
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var isScanning by remember { mutableStateOf(false) }
    val analysisResults by analyzer.analysisResults.collectAsState()
    var scanCallback by remember { mutableStateOf<ScanCallback?>(null) }
    var expandedDevices by remember { mutableStateOf(setOf<String>()) }

    val sortedResults = analysisResults.values.sortedWith(
        compareByDescending<DeviceAnalysisResult> {
            when(it.riskLevel) {
                RiskLevel.HIGH -> 3
                RiskLevel.MEDIUM -> 2
                RiskLevel.LOW -> 1
            }
        }.thenBy { it.name ?: it.address }
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("BLE Security Mapper") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary
                )
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            if (analysisResults.isNotEmpty() && !isScanning) {
                AreaSafetySummaryCompact(analysisResults.values.toList())
                Spacer(modifier = Modifier.height(8.dp))
            }

            Button(
                onClick = {
                    if (isScanning) {
                        scanCallback?.let { stopBleScan(context, it) }
                        isScanning = false
                    } else {
                        analyzer.reset()
                        isScanning = true

                        scope.launch {
                            val callback = startBleScan(context, analyzer)
                            scanCallback = callback
                            delay(90000)
                            callback?.let { stopBleScan(context, it) }
                            isScanning = false
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth().height(48.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isScanning) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.primary
                )
            ) {
                Icon(
                    imageVector = if (isScanning) Icons.Default.Stop else Icons.Default.PlayArrow,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = if (isScanning) "STOP SCAN" else "START SCAN (90s)",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (isScanning) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer
                    )
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(10.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Scanning...", fontSize = 13.sp)
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            if (analysisResults.isNotEmpty()) {
                val summary = analyzer.getAreaSafetySummary()
                StatsCardCompact(summary)
                Spacer(modifier = Modifier.height(8.dp))
            }

            if (analysisResults.isEmpty() && !isScanning) {
                EmptyStateView()
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(sortedResults) { result ->
                        DeviceCard(
                            result = result,
                            isExpanded = expandedDevices.contains(result.address),
                            onToggleExpand = {
                                expandedDevices = if (expandedDevices.contains(result.address)) {
                                    expandedDevices - result.address
                                } else {
                                    expandedDevices + result.address
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AreaSafetySummaryCompact(results: List<DeviceAnalysisResult>) {
    val highRisk = results.count { it.riskLevel == RiskLevel.HIGH }
    val mediumRisk = results.count { it.riskLevel == RiskLevel.MEDIUM }

    val safetyLevel: String
    val safetyColor: Color
    val safetyIcon: androidx.compose.ui.graphics.vector.ImageVector

    when {
        highRisk >= 3 -> {
            safetyLevel = "DANGER"
            safetyColor = Color(0xFFD32F2F)
            safetyIcon = Icons.Default.Warning
        }
        highRisk >= 1 -> {
            safetyLevel = "WARNING"
            safetyColor = Color(0xFFF57C00)
            safetyIcon = Icons.Default.Warning
        }
        mediumRisk >= 2 -> {
            safetyLevel = "CAUTION"
            safetyColor = Color(0xFFFFA726)
            safetyIcon = Icons.Default.Info
        }
        else -> {
            safetyLevel = "SAFE"
            safetyColor = Color(0xFF43A047)
            safetyIcon = Icons.Default.CheckCircle
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = safetyColor.copy(alpha = 0.1f)
        )
    ) {
        Row(
            modifier = Modifier.padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = safetyIcon,
                contentDescription = null,
                tint = safetyColor,
                modifier = Modifier.size(28.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = "Area: $safetyLevel",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = safetyColor
            )
        }
    }
}

@Composable
fun StatsCardCompact(summary: AreaSafetySummary) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(10.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            StatItemCompact("Total", summary.totalDevices.toString(), Color.Gray)
            StatItemCompact("🔴", summary.highRiskDevices.toString(), Color(0xFFE53935))
            StatItemCompact("🟡", summary.mediumRiskDevices.toString(), Color(0xFFFB8C00))
            StatItemCompact("🟢", summary.lowRiskDevices.toString(), Color(0xFF43A047))
        }
    }
}

@Composable
fun StatItemCompact(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(text = value, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = color)
        Text(text = label, fontSize = 11.sp, color = Color.Gray)
    }
}

@Composable
fun DeviceCard(
    result: DeviceAnalysisResult,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit
) {
    val riskColor = when (result.riskLevel) {
        RiskLevel.HIGH -> Color(0xFFE53935)
        RiskLevel.MEDIUM -> Color(0xFFFB8C00)
        RiskLevel.LOW -> Color(0xFF43A047)
    }

    val riskEmoji = when (result.riskLevel) {
        RiskLevel.HIGH -> "🔴"
        RiskLevel.MEDIUM -> "🟡"
        RiskLevel.LOW -> "🟢"
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(riskEmoji, fontSize = 16.sp)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = result.name ?: "Unknown Device",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp
                        )
                    }

                    Text(
                        text = result.address,
                        fontSize = 11.sp,
                        color = Color.Gray
                    )

                    if (result.vulnerabilities.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "⚠️ ${result.vulnerabilities.size} ${if (result.vulnerabilities.size == 1) "vulnerability" else "vulnerabilities"}",
                            fontSize = 12.sp,
                            color = riskColor,
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    Spacer(modifier = Modifier.height(3.dp))
                    Text(
                        "📍 ${result.rssi}dBm • 📊 ${result.observationCount} obs",
                        fontSize = 10.sp,
                        color = Color.Gray
                    )
                }

                Box(
                    modifier = Modifier
                        .background(
                            riskColor.copy(alpha = 0.2f),
                            RoundedCornerShape(12.dp)
                        )
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        "${result.riskLevel}",
                        color = riskColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp
                    )
                }
            }

            if (result.vulnerabilities.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))

                val vulnTypes = result.vulnerabilities.groupBy { it.title }
                vulnTypes.keys.take(3).forEach { title ->
                    Text(
                        "• $title",
                        fontSize = 11.sp,
                        color = riskColor,
                        modifier = Modifier.padding(vertical = 1.dp)
                    )
                }

                if (vulnTypes.size > 3) {
                    Text(
                        "• +${vulnTypes.size - 3} more...",
                        fontSize = 11.sp,
                        color = Color.Gray
                    )
                }
            }

            if (result.vulnerabilities.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onToggleExpand,
                    modifier = Modifier.fillMaxWidth().height(36.dp),
                    contentPadding = PaddingValues(horizontal = 8.dp)
                ) {
                    Text(if (isExpanded) "Hide Details" else "Show Details", fontSize = 12.sp)
                    Spacer(modifier = Modifier.width(4.dp))
                    Icon(
                        if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        null,
                        modifier = Modifier.size(14.dp)
                    )
                }
            }

            if (isExpanded && result.vulnerabilities.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                result.vulnerabilities.forEach { vuln ->
                    VulnerabilityItemCompact(vuln)
                    Spacer(modifier = Modifier.height(6.dp))
                }
            }
        }
    }
}

@Composable
fun VulnerabilityItemCompact(vulnerability: Vulnerability) {
    val severityColor = when (vulnerability.severity) {
        VulnerabilitySeverity.CRITICAL -> Color(0xFFB71C1C)
        VulnerabilitySeverity.HIGH -> Color(0xFFE53935)
        VulnerabilitySeverity.MEDIUM -> Color(0xFFFB8C00)
        VulnerabilitySeverity.LOW -> Color(0xFFFFA726)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = severityColor.copy(alpha = 0.1f))
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(vulnerability.title, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.weight(1f))
                Text(vulnerability.severity.name, color = severityColor, fontWeight = FontWeight.Bold, fontSize = 10.sp)
            }

            Spacer(modifier = Modifier.height(4.dp))
            Text(vulnerability.description, fontSize = 11.sp, color = Color.Gray)

            Spacer(modifier = Modifier.height(6.dp))
            Text("Evidence:", fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
            Text(vulnerability.evidence, fontSize = 10.sp, color = Color.DarkGray)

            Spacer(modifier = Modifier.height(6.dp))
            Text("Fix:", fontWeight = FontWeight.SemiBold, fontSize = 11.sp, color = Color(0xFF1976D2))
            Text(vulnerability.recommendation, fontSize = 10.sp, color = Color(0xFF1976D2))
        }
    }
}

@Composable
fun EmptyStateView() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.Search, null, modifier = Modifier.size(48.dp), tint = Color.Gray)
            Spacer(modifier = Modifier.height(12.dp))
            Text("No devices found", fontSize = 16.sp, color = Color.Gray)
            Text("Tap START SCAN", fontSize = 13.sp, color = Color.Gray)
        }
    }
}

@SuppressLint("MissingPermission")
fun startBleScan(context: Context, analyzer: SecurityAnalyzer): ScanCallback {
    val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    val bluetoothAdapter = bluetoothManager.adapter
    val scanner = bluetoothAdapter.bluetoothLeScanner

    val settings = ScanSettings.Builder()
        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
        .build()

    val callback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            analyzer.analyzeDevice(result)
        }
    }

    scanner.startScan(null, settings, callback)
    return callback
}

@SuppressLint("MissingPermission")
fun stopBleScan(context: Context, callback: ScanCallback) {
    val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    val bluetoothAdapter = bluetoothManager.adapter
    bluetoothAdapter.bluetoothLeScanner?.stopScan(callback)
}
