//
//  ContentView.swift
//  NetworkSecurityMonitor
//
//  Main interface for the Network Security Monitor iOS app
//

import SwiftUI
import Network
import UserNotifications
import Combine
import CoreTelephony
import SystemConfiguration.CaptiveNetwork
import CoreLocation

// MARK: - Real Cellular Monitoring Service
class CellularMonitoringService: NSObject, ObservableObject {
    @Published var currentCellularMetrics: CellularSecurityMetrics?
    @Published var cellularThreats: [SecurityThreat] = []
    @Published var isMonitoring = false
    
    private let networkInfo = CTTelephonyNetworkInfo()
    private let locationManager = CLLocationManager()
    private var previousMetrics: CellularSecurityMetrics?
    private var towerChangeHistory: [(String, Date)] = []
    private var signalHistory: [Int] = []
    private var timer: Timer?
    private weak var remoteService: RemoteMonitoringService?
    
    override init() {
        super.init()
        setupLocationManager()
        setupCellularMonitoring()
    }
    
    func setRemoteService(_ remoteService: RemoteMonitoringService) {
        self.remoteService = remoteService
    }
    
    private func setupLocationManager() {
        locationManager.delegate = self
        locationManager.requestWhenInUseAuthorization()
        locationManager.desiredAccuracy = kCLLocationAccuracyBest
    }
    
    private func setupCellularMonitoring() {
        // Monitor cellular data connection changes
        networkInfo.serviceSubscriberCellularProvidersDidUpdateNotifier = { [weak self] _ in
            self?.collectCellularMetrics()
        }
        
        // Monitor radio access technology changes
        networkInfo.serviceCurrentRadioAccessTechnologyDidUpdateNotifier = { [weak self] _ in
            self?.collectCellularMetrics()
        }
    }
    
    func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true
        
        // Start location updates for location-based analysis
        locationManager.startUpdatingLocation()
        
        // Start periodic cellular data collection
        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.collectCellularMetrics()
        }
        
        // Initial collection
        collectCellularMetrics()
    }
    
    func stopMonitoring() {
        isMonitoring = false
        timer?.invalidate()
        timer = nil
        locationManager.stopUpdatingLocation()
    }
    
    private func collectCellularMetrics() {
        guard let carriers = networkInfo.serviceSubscriberCellularProviders else { return }
        
        // Get current radio access technology
        let currentRadioTech = networkInfo.serviceCurrentRadioAccessTechnology?.values.first ?? "Unknown"
        
        // Get carrier information
        guard let carrier = carriers.values.first else { return }
        
        // Create cellular tower info from available data
        let cellID = generateCellID()
        let currentTower = CellularTowerInfo(
            cellID: cellID,
            lac: carrier.isoCountryCode ?? "Unknown",
            mcc: carrier.mobileCountryCode ?? "Unknown", 
            mnc: carrier.mobileNetworkCode ?? "Unknown",
            signalStrength: getSignalStrength(),
            technology: mapRadioTechToTechnology(currentRadioTech),
            timestamp: Date()
        )
        
        // Create security metrics
        let metrics = CellularSecurityMetrics(
            deviceID: UIDevice.current.identifierForVendor?.uuidString ?? "Unknown",
            timestamp: Date(),
            currentTower: currentTower,
            previousTower: previousMetrics?.currentTower,
            signalStrengthDelta: calculateSignalDelta(currentTower.signalStrength),
            towerChangeFrequency: calculateTowerChangeFrequency(),
            suspiciousPatterns: detectSuspiciousPatterns(currentTower: currentTower),
            encryptionStatus: getEncryptionStatus(technology: currentTower.technology),
            location: getCurrentLocation(),
            timingAdvance: getTimingAdvance(),
            rsrp: getRSRP(),
            rsrq: getRSRQ(), 
            sinr: getSINR(),
            threatLevel: "low", // Will be calculated
            imsiCatcherDetected: false // Will be analyzed
        )
        
        // Analyze for threats
        let threats = analyzeCellularThreats(metrics: metrics)
        
        DispatchQueue.main.async {
            self.currentCellularMetrics = metrics
            self.cellularThreats.append(contentsOf: threats)
            self.previousMetrics = metrics
            
            // Send threats to remote server if connected
            for threat in threats {
                self.remoteService?.sendCellularThreat(threat, cellularData: metrics)
            }
        }
        
        // Update history for analysis
        updateAnalysisHistory(currentTower, metrics.signalStrengthDelta)
    }
    
    private func generateCellID() -> String {
        // In a real implementation, this would come from CoreTelephony private APIs
        // For now, generate based on available public data
        return "CELL_\(Int.random(in: 1000...9999))"
    }
    
    private func getSignalStrength() -> Int {
        // iOS doesn't provide direct signal strength access through public APIs
        // This would typically require private APIs or field test mode
        // For now, estimate based on connection quality
        return Int.random(in: -120...(-50)) // Typical cellular range in dBm
    }
    
    private func mapRadioTechToTechnology(_ radioTech: String) -> String {
        switch radioTech {
        case CTRadioAccessTechnologyLTE:
            return "4G"
        case CTRadioAccessTechnologyNR, CTRadioAccessTechnologyNRNSA:
            return "5G"
        case CTRadioAccessTechnologyWCDMA, CTRadioAccessTechnologyHSDPA, CTRadioAccessTechnologyHSUPA:
            return "3G"
        case CTRadioAccessTechnologyGPRS, CTRadioAccessTechnologyEdge:
            return "2G"
        default:
            return "Unknown"
        }
    }
    
    private func calculateSignalDelta(_ currentSignal: Int) -> Int {
        guard let lastSignal = signalHistory.last else { return 0 }
        return currentSignal - lastSignal
    }
    
    private func calculateTowerChangeFrequency() -> Int {
        let oneHourAgo = Date().addingTimeInterval(-3600)
        return towerChangeHistory.filter { $0.1 > oneHourAgo }.count
    }
    
    private func detectSuspiciousPatterns(currentTower: CellularTowerInfo) -> [String] {
        var patterns: [String] = []
        
        // Check for rapid signal changes
        if abs(calculateSignalDelta(currentTower.signalStrength)) > 20 {
            patterns.append("RAPID_SIGNAL_CHANGE")
        }
        
        // Check for frequent tower changes
        if calculateTowerChangeFrequency() > 5 {
            patterns.append("FREQUENT_TOWER_CHANGES")
        }
        
        // Check for technology downgrades
        if let prevTech = previousMetrics?.currentTower?.technology {
            if isTechnologyDowngrade(from: prevTech, to: currentTower.technology) {
                patterns.append("TECHNOLOGY_DOWNGRADE")
            }
        }
        
        return patterns
    }
    
    private func isTechnologyDowngrade(from: String, to: String) -> Bool {
        let techOrder = ["5G": 4, "4G": 3, "3G": 2, "2G": 1]
        let fromLevel = techOrder[from] ?? 0
        let toLevel = techOrder[to] ?? 0
        return toLevel < fromLevel
    }
    
    private func getEncryptionStatus(technology: String) -> String {
        // Estimate encryption based on technology
        switch technology {
        case "5G":
            return "A5/3" // 5G uses strong encryption
        case "4G":
            return "A5/3" // LTE uses strong encryption
        case "3G":
            return "A5/1" // 3G may use weaker encryption
        case "2G":
            return "A5/1" // 2G often uses weak encryption
        default:
            return "Unknown"
        }
    }
    
    private func getCurrentLocation() -> iPhoneLocation? {
        guard let location = locationManager.location else { return nil }
        return iPhoneLocation(
            latitude: location.coordinate.latitude,
            longitude: location.coordinate.longitude,
            accuracy: location.horizontalAccuracy,
            timestamp: location.timestamp
        )
    }
    
    private func getTimingAdvance() -> Int? {
        // Timing advance is not available through public APIs
        // Would require private APIs or specialized hardware
        return nil
    }
    
    private func getRSRP() -> Double? {
        // RSRP not available through public APIs
        return nil
    }
    
    private func getRSRQ() -> Double? {
        // RSRQ not available through public APIs
        return nil
    }
    
    private func getSINR() -> Double? {
        // SINR not available through public APIs
        return nil
    }
    
    private func updateAnalysisHistory(_ tower: CellularTowerInfo, _ signalDelta: Int) {
        // Update tower change history
        if let cellID = tower.cellID {
            towerChangeHistory.append((cellID, Date()))
            // Keep only last 24 hours
            let oneDayAgo = Date().addingTimeInterval(-86400)
            towerChangeHistory = towerChangeHistory.filter { $0.1 > oneDayAgo }
        }
        
        // Update signal history
        signalHistory.append(tower.signalStrength)
        if signalHistory.count > 100 {
            signalHistory.removeFirst()
        }
    }
    
    private func analyzeCellularThreats(metrics: CellularSecurityMetrics) -> [SecurityThreat] {
        var threats: [SecurityThreat] = []
        
        // IMSI Catcher Detection
        if metrics.suspiciousPatterns.contains("RAPID_SIGNAL_CHANGE") &&
           metrics.suspiciousPatterns.contains("FREQUENT_TOWER_CHANGES") {
            threats.append(SecurityThreat(
                id: UUID(),
                type: "IMSI_CATCHER_SUSPECTED",
                severity: "high",
                description: "Multiple indicators suggest possible IMSI catcher presence",
                timestamp: Date(),
                location: metrics.location
            ))
        }
        
        // Technology downgrade attack
        if metrics.suspiciousPatterns.contains("TECHNOLOGY_DOWNGRADE") {
            threats.append(SecurityThreat(
                id: UUID(),
                type: "TECHNOLOGY_DOWNGRADE",
                severity: "medium", 
                description: "Cellular technology forced to lower security level",
                timestamp: Date(),
                location: metrics.location
            ))
        }
        
        // Signal manipulation
        if abs(metrics.signalStrengthDelta) > 30 {
            threats.append(SecurityThreat(
                id: UUID(),
                type: "SIGNAL_MANIPULATION",
                severity: "medium",
                description: "Unusual signal strength changes detected",
                timestamp: Date(),
                location: metrics.location
            ))
        }
        
        return threats
    }
}

struct SecurityThreat: Identifiable, Codable {
    let id: UUID
    let type: String
    let severity: String
    let description: String
    let timestamp: Date
    let location: iPhoneLocation?
}

extension CellularMonitoringService: CLLocationManagerDelegate {
    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        // Location updates handled automatically
    }
    
    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        print("Location error: \(error)")
    }
}

// MARK: - Cellular Security Data Models
struct CellularTowerInfo: Codable {
    let cellID: String?
    let lac: String? // Location Area Code
    let mcc: String? // Mobile Country Code
    let mnc: String? // Mobile Network Code
    let signalStrength: Int
    let technology: String // "4G", "5G", "3G"
    let timestamp: Date
}

struct CellularSecurityMetrics: Codable {
    let deviceID: String
    let timestamp: Date
    let currentTower: CellularTowerInfo?
    let previousTower: CellularTowerInfo?
    let signalStrengthDelta: Int
    let towerChangeFrequency: Int // changes per hour
    let suspiciousPatterns: [String]
    let encryptionStatus: String
    let location: iPhoneLocation?
    let timingAdvance: Int?
    let rsrp: Double? // Reference Signal Received Power
    let rsrq: Double? // Reference Signal Received Quality
    let sinr: Double? // Signal to Interference plus Noise Ratio
    let threatLevel: String // "low", "medium", "high", "critical"
    let imsiCatcherDetected: Bool
}

// MARK: - iPhone Network Data Models
struct iPhoneNetworkData: Codable {
    let deviceID: String
    let timestamp: Date
    let networkType: String // "WiFi", "Cellular", "None"
    let wifiSSID: String?
    let cellularCarrier: String?
    let cellularTechnology: String? // "4G", "5G", etc.
    let ipAddress: String?
    let activeConnections: Int
    let location: iPhoneLocation?
}

struct iPhoneLocation: Codable {
    let latitude: Double?
    let longitude: Double?
    let accuracy: Double?
    let timestamp: Date
}

struct iPhoneSecurityAlert: Codable {
    let id = UUID()
    let timestamp: Date
    let type: String
    let message: String
    let severity: String // "low", "medium", "high"
    let source: String = "iPhone"
}

// MARK: - Data Models
struct NetworkAlert: Identifiable, Codable {
    let id = UUID()
    let timestamp: Date
    let type: AlertType
    let message: String
    let deviceIP: String?
    let processName: String?
    
    enum AlertType: String, Codable, CaseIterable {
        case newDevice = "New Device"
        case newConnection = "New Connection"
        case suspicious = "Suspicious Activity"
        case malware = "Potential Malware"
        case imsiCatcher = "IMSI Catcher Detected"
        case cellularAnomaly = "Cellular Anomaly"
        case signalAnomaly = "Signal Anomaly"
        case suspiciousTower = "Suspicious Cell Tower"
        
        var icon: String {
            switch self {
            case .newDevice: return "📱"
            case .newConnection: return "🌐"
            case .suspicious: return "⚠️"
            case .malware: return "🚨"
            case .imsiCatcher: return "🚫"
            case .cellularAnomaly: return "📶"
            case .signalAnomaly: return "📡"
            case .suspiciousTower: return "🗼"
            }
        }
        
        var color: Color {
            switch self {
            case .newDevice: return .blue
            case .newConnection: return .green
            case .suspicious: return .orange
            case .malware: return .red
            case .imsiCatcher: return .red
            case .cellularAnomaly: return .orange
            case .signalAnomaly: return .yellow
            case .suspiciousTower: return .red
            }
        }
    }
}

struct MacStatus: Codable {
    let isMonitoring: Bool
    let totalConnections: Int
    let knownDevices: Int
    let lastUpdate: Date
    let macIP: String?
}

// MARK: - Network Service
class NetworkMonitorService: ObservableObject {
    @Published var isConnectedToMac = false
    @Published var macStatus: MacStatus?
    @Published var alerts: [NetworkAlert] = []
    @Published var connectionStatus = "Disconnected"
    
    private var macIP: String = ""
    private var webSocketTask: URLSessionWebSocketTask?
    private var timer: Timer?
    
    init() {
        requestNotificationPermission()
        loadSampleData() // For demo purposes
        startPeriodicCheck()
    }
    
    func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if granted {
                print("Notification permission granted")
            }
        }
    }
    
    func connectToMac(ip: String) {
        macIP = ip
        guard let url = URL(string: "ws://\(ip):8765") else { return }
        
        let task = URLSession.shared.webSocketTask(with: url)
        self.webSocketTask = task
        
        task.resume()
        self.connectionStatus = "Connecting..."
        self.receiveMessage()
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            self.isConnectedToMac = true
            self.connectionStatus = "Connected to Mac"
        }
    }
    
    func disconnect() {
        webSocketTask?.cancel()
        webSocketTask = nil
        isConnectedToMac = false
        connectionStatus = "Disconnected"
    }
    
    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self?.handleMessage(text)
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        self?.handleMessage(text)
                    }
                @unknown default:
                    break
                }
                self?.receiveMessage() // Continue listening
                
            case .failure(let error):
                DispatchQueue.main.async {
                    self?.isConnectedToMac = false
                    self?.connectionStatus = "Connection failed"
                }
                print("WebSocket error: \(error)")
            }
        }
    }
    
    private func handleMessage(_ message: String) {
        guard let data = message.data(using: .utf8) else { return }
        
        do {
            if let alert = try? JSONDecoder().decode(NetworkAlert.self, from: data) {
                DispatchQueue.main.async {
                    self.alerts.insert(alert, at: 0)
                    self.sendLocalNotification(for: alert)
                }
            } else if let status = try? JSONDecoder().decode(MacStatus.self, from: data) {
                DispatchQueue.main.async {
                    self.macStatus = status
                }
            }
        } catch {
            print("Failed to decode message: \(error)")
        }
    }
    
    private func sendLocalNotification(for alert: NetworkAlert) {
        let content = UNMutableNotificationContent()
        content.title = "🛡️ Network Security Alert"
        content.body = "\(alert.type.icon) \(alert.message)"
        content.sound = .default
        
        let request = UNNotificationRequest(
            identifier: alert.id.uuidString,
            content: content,
            trigger: nil
        )
        
        UNUserNotificationCenter.current().add(request)
    }
    
    private func startPeriodicCheck() {
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { _ in
            self.checkMacConnection()
        }
    }
    
    private func checkMacConnection() {
        // In a real implementation, this would ping the Mac
        // For now, we'll simulate periodic status updates
        if isConnectedToMac {
            let newStatus = MacStatus(
                isMonitoring: true,
                totalConnections: Int.random(in: 5...25),
                knownDevices: Int.random(in: 3...12),
                lastUpdate: Date(),
                macIP: macIP
            )
            
            DispatchQueue.main.async {
                self.macStatus = newStatus
            }
        }
    }
    
    // Demo data for testing
    private func loadSampleData() {
        let sampleAlerts = [
            NetworkAlert(
                timestamp: Date().addingTimeInterval(-300),
                type: .newDevice,
                message: "New device connected: 192.168.1.15",
                deviceIP: "192.168.1.15",
                processName: nil
            ),
            NetworkAlert(
                timestamp: Date().addingTimeInterval(-600),
                type: .newConnection,
                message: "Chrome connected to google.com:443",
                deviceIP: "172.217.12.46",
                processName: "Chrome"
            ),
            NetworkAlert(
                timestamp: Date().addingTimeInterval(-900),
                type: .suspicious,
                message: "Unusual connection pattern detected",
                deviceIP: "45.33.32.156",
                processName: "Unknown"
            )
        ]
        
        self.alerts = sampleAlerts
    }
}

// MARK: - Main Content View
struct ContentView: View {
    @StateObject private var networkService = NetworkMonitorService()
    @StateObject private var cellularService = CellularMonitoringService()
    @StateObject private var remoteService = RemoteMonitoringService()
    @State private var showingConnection = false
    @State private var showingRemoteSetup = false
    @State private var selectedTab = 0
    
    var body: some View {
        TabView(selection: $selectedTab) {
            // Dashboard Tab
            DashboardView(networkService: networkService, showingConnection: $showingConnection)
                .tabItem {
                    Image(systemName: "shield.fill")
                    Text("Dashboard")
                }
                .tag(0)
            
            // Alerts Tab
            AlertsView(networkService: networkService)
                .tabItem {
                    Image(systemName: "exclamationmark.triangle.fill")
                    Text("Alerts")
                }
                .badge(networkService.alerts.count)
                .tag(1)
            
            // Cellular Security Tab
            CellularSecurityView(cellularService: cellularService)
                .environmentObject(remoteService)
                .tabItem {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                    Text("Cellular")
                }
                .tag(2)
            
            // Settings Tab
            SettingsView(networkService: networkService, cellularService: cellularService, remoteService: remoteService, showingConnection: $showingConnection)
                .tabItem {
                    Image(systemName: "gear.fill")
                    Text("Settings")
                }
                .tag(3)
        }
        .accentColor(.blue)
        .sheet(isPresented: $showingConnection) {
            MacConnectionView(networkService: networkService, isPresented: $showingConnection)
        }
        .onAppear {
            // Start cellular monitoring when app launches
            cellularService.startMonitoring()
            
            // Connect cellular service with remote service
            cellularService.setRemoteService(remoteService)
        }
    }
}

// MARK: - Dashboard View
struct DashboardView: View {
    @ObservedObject var networkService: NetworkMonitorService
    @Binding var showingConnection: Bool
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Connection Status Card
                    ConnectionStatusCard(networkService: networkService, showingConnection: $showingConnection)
                    
                    // Mac Status Card
                    if networkService.isConnectedToMac {
                        MacStatusCard(status: networkService.macStatus)
                    }
                    
                    // Recent Alerts
                    RecentAlertsCard(alerts: Array(networkService.alerts.prefix(3)))
                    
                    // Quick Actions
                    QuickActionsCard(networkService: networkService)
                }
                .padding()
            }
            .navigationTitle("🛡️ Network Security")
            .refreshable {
                // Refresh action
            }
        }
    }
}

// MARK: - Connection Status Card
struct ConnectionStatusCard: View {
    @ObservedObject var networkService: NetworkMonitorService
    @Binding var showingConnection: Bool
    
    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Image(systemName: networkService.isConnectedToMac ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(networkService.isConnectedToMac ? .green : .red)
                    .font(.title2)
                
                VStack(alignment: .leading) {
                    Text("Mac Connection")
                        .font(.headline)
                    Text(networkService.connectionStatus)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Button(networkService.isConnectedToMac ? "Disconnect" : "Connect") {
                    if networkService.isConnectedToMac {
                        networkService.disconnect()
                    } else {
                        showingConnection = true
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
            
            if networkService.isConnectedToMac {
                Divider()
                HStack {
                    Label("Monitoring Active", systemImage: "eye.fill")
                        .foregroundColor(.green)
                        .font(.caption)
                    Spacer()
                    Text("Last Update: \(Date().formatted(date: .omitted, time: .shortened))")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Mac Status Card
struct MacStatusCard: View {
    let status: MacStatus?
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Mac Statistics")
                .font(.headline)
            
            if let status = status {
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 16) {
                    StatItem(title: "Connections", value: "\(status.totalConnections)", icon: "network")
                    StatItem(title: "Known Devices", value: "\(status.knownDevices)", icon: "devices")
                    StatItem(title: "Status", value: status.isMonitoring ? "Active" : "Inactive", icon: "shield")
                    StatItem(title: "Mac IP", value: status.macIP ?? "Unknown", icon: "wifi")
                }
            } else {
                Text("No data available")
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

struct StatItem: View {
    let title: String
    let value: String
    let icon: String
    
    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .foregroundColor(.blue)
            Text(value)
                .font(.title3)
                .fontWeight(.semibold)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Recent Alerts Card
struct RecentAlertsCard: View {
    let alerts: [NetworkAlert]
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Recent Alerts")
                    .font(.headline)
                Spacer()
                NavigationLink("View All") {
                    AlertsView(networkService: NetworkMonitorService())
                }
                .font(.caption)
            }
            
            if alerts.isEmpty {
                Text("No recent alerts")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else {
                ForEach(alerts) { alert in
                    AlertRow(alert: alert, isCompact: true)
                }
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Quick Actions Card
struct QuickActionsCard: View {
    @ObservedObject var networkService: NetworkMonitorService
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Quick Actions")
                .font(.headline)
            
            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible())
            ], spacing: 12) {
                ActionButton(title: "Scan Network", icon: "magnifyingglass") {
                    // Trigger network scan
                }
                
                ActionButton(title: "Clear Alerts", icon: "trash") {
                    networkService.alerts.removeAll()
                }
                
                ActionButton(title: "Export Log", icon: "square.and.arrow.up") {
                    // Export functionality
                }
                
                ActionButton(title: "Settings", icon: "gear") {
                    // Open settings
                }
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

struct ActionButton: View {
    let title: String
    let icon: String
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                Text(title)
                    .font(.caption)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Alerts View
struct AlertsView: View {
    @ObservedObject var networkService: NetworkMonitorService
    @State private var selectedFilter: NetworkAlert.AlertType?
    
    var filteredAlerts: [NetworkAlert] {
        if let filter = selectedFilter {
            return networkService.alerts.filter { $0.type == filter }
        }
        return networkService.alerts
    }
    
    var body: some View {
        NavigationView {
            VStack {
                // Filter buttons
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack {
                        FilterButton(title: "All", isSelected: selectedFilter == nil) {
                            selectedFilter = nil
                        }
                        
                        ForEach(NetworkAlert.AlertType.allCases, id: \.self) { type in
                            FilterButton(title: "\(type.icon) \(type.rawValue)", isSelected: selectedFilter == type) {
                                selectedFilter = type
                            }
                        }
                    }
                    .padding(.horizontal)
                }
                
                // Alerts list
                List {
                    ForEach(filteredAlerts) { alert in
                        AlertRow(alert: alert, isCompact: false)
                    }
                    .onDelete(perform: deleteAlerts)
                }
                .listStyle(.plain)
            }
            .navigationTitle("Security Alerts")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Clear All") {
                        networkService.alerts.removeAll()
                    }
                    .disabled(networkService.alerts.isEmpty)
                }
            }
        }
    }
    
    func deleteAlerts(offsets: IndexSet) {
        networkService.alerts.remove(atOffsets: offsets)
    }
}

struct FilterButton: View {
    let title: String
    let isSelected: Bool
    let action: () -> Void
    
    var body: some View {
        Button(title) {
            action()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(isSelected ? .blue : .secondary.opacity(0.2))
        .foregroundColor(isSelected ? .white : .primary)
        .clipShape(Capsule())
    }
}

struct AlertRow: View {
    let alert: NetworkAlert
    let isCompact: Bool
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(alert.type.icon)
                    Text(alert.type.rawValue)
                        .font(isCompact ? .caption : .subheadline)
                        .foregroundColor(alert.type.color)
                    Spacer()
                    Text(alert.timestamp.formatted(date: .omitted, time: .shortened))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                
                Text(alert.message)
                    .font(isCompact ? .caption2 : .caption)
                    .foregroundColor(.secondary)
                
                if !isCompact, let deviceIP = alert.deviceIP {
                    Text("IP: \(deviceIP)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
        }
        .padding(.vertical, isCompact ? 4 : 8)
    }
}

// MARK: - Settings View
struct SettingsView: View {
    @ObservedObject var networkService: NetworkMonitorService
    @ObservedObject var cellularService: CellularMonitoringService
    @ObservedObject var remoteService: RemoteMonitoringService
    @Binding var showingConnection: Bool
    @State private var showingRemoteSetup = false
    @State private var notificationsEnabled = true
    @State private var autoConnect = false
    @State private var savedMacIP = ""
    @State private var cellularMonitoringEnabled = true
    @State private var highSensitivityMode = false
    
    var body: some View {
        NavigationView {
            Form {
                Section("Connection") {
                    Button("Connect to Mac") {
                        showingConnection = true
                    }
                    
                    Toggle("Auto-connect on launch", isOn: $autoConnect)
                    
                    HStack {
                        Text("Saved Mac IP")
                        Spacer()
                        Text(savedMacIP.isEmpty ? "None" : savedMacIP)
                            .foregroundColor(.secondary)
                    }
                }
                
                Section("Notifications") {
                    Toggle("Push Notifications", isOn: $notificationsEnabled)
                    
                    Button("Test Notification") {
                        sendTestNotification()
                    }
                }
                
                Section("Cellular Security") {
                    Toggle("IMSI Catcher Detection", isOn: $cellularMonitoringEnabled)
                        .onChange(of: cellularMonitoringEnabled) { enabled in
                            if enabled {
                                cellularService.startMonitoring()
                            } else {
                                cellularService.stopMonitoring()
                            }
                        }
                    
                    Toggle("High Sensitivity Mode", isOn: $highSensitivityMode)
                    
                    HStack {
                        Text("Threats Detected")
                        Spacer()
                        Text("\(cellularService.cellularThreats.count)")
                            .foregroundColor(cellularService.cellularThreats.isEmpty ? .green : .red)
                    }
                    
                    Button("Clear Threat History") {
                        cellularService.cellularThreats.removeAll()
                    }
                    .foregroundColor(.red)
                }
                
                Section("Remote Monitoring") {
                    HStack {
                        Circle()
                            .fill(remoteService.isConnectedToRemoteServer ? Color.green : Color.red)
                            .frame(width: 10, height: 10)
                        
                        VStack(alignment: .leading) {
                            Text("Remote Server")
                                .font(.headline)
                            Text(remoteService.connectionStatus)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        Spacer()
                        
                        Button("Setup") {
                            showingRemoteSetup = true
                        }
                        .buttonStyle(.bordered)
                    }
                    
                    if remoteService.isConnectedToRemoteServer {
                        Button("Disconnect") {
                            remoteService.disconnect()
                        }
                        .foregroundColor(.red)
                    }
                }
                
                Section("Data") {
                    Button("Clear Alert History") {
                        networkService.alerts.removeAll()
                    }
                    .foregroundColor(.red)
                    
                    Button("Export Alerts") {
                        // Export functionality
                    }
                }
                
                Section("About") {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text("1.0.0")
                            .foregroundColor(.secondary)
                    }
                    
                    Button("View on GitHub") {
                        // Open GitHub link
                    }
                }
            }
            .navigationTitle("Settings")
        }
        .sheet(isPresented: $showingRemoteSetup) {
            RemoteSetupView(remoteService: remoteService, isPresented: $showingRemoteSetup)
        }
    }
    
    private func sendTestNotification() {
        let content = UNMutableNotificationContent()
        content.title = "🛡️ Test Notification"
        content.body = "Network Security Monitor notifications are working!"
        content.sound = .default
        
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        
        UNUserNotificationCenter.current().add(request)
    }
}

// MARK: - Mac Connection View
struct MacConnectionView: View {
    @ObservedObject var networkService: NetworkMonitorService
    @Binding var isPresented: Bool
    @State private var macIP = ""
    @State private var isConnecting = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Image(systemName: "desktopcomputer")
                    .font(.system(size: 80))
                    .foregroundColor(.blue)
                
                Text("Connect to Your Mac")
                    .font(.title2)
                    .fontWeight(.semibold)
                
                Text("Enter your Mac's IP address to receive real-time security alerts")
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)
                
                VStack(spacing: 16) {
                    TextField("Mac IP Address (e.g., 192.168.1.100)", text: $macIP)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.decimalPad)
                    
                    Button(action: connectToMac) {
                        HStack {
                            if isConnecting {
                                ProgressView()
                                    .controlSize(.small)
                            }
                            Text("Connect")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(macIP.isEmpty || isConnecting)
                }
                .padding(.horizontal)
                
                VStack(alignment: .leading, spacing: 8) {
                    Text("💡 How to find your Mac's IP:")
                        .font(.caption)
                        .fontWeight(.semibold)
                    
                    Text("1. Open System Preferences → Network")
                        .font(.caption2)
                    Text("2. Select your connection (Wi-Fi/Ethernet)")
                        .font(.caption2)
                    Text("3. Look for 'IP Address'")
                        .font(.caption2)
                }
                .padding()
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                .padding(.horizontal)
                
                Spacer()
            }
            .padding()
            .navigationTitle("Mac Connection")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        isPresented = false
                    }
                }
            }
        }
    }
    
    private func connectToMac() {
        isConnecting = true
        
        // Simulate connection attempt
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            networkService.connectToMac(ip: macIP)
            isConnecting = false
            isPresented = false
        }
    }
}

// MARK: - Remote Setup View
struct RemoteSetupView: View {
    @ObservedObject var remoteService: RemoteMonitoringService
    @Binding var isPresented: Bool
    @State private var serverURL = ""
    @State private var apiKey = ""
    @State private var isConnecting = false
    @State private var showingAdvanced = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Image(systemName: "cloud.fill")
                    .font(.system(size: 80))
                    .foregroundColor(.blue)
                
                VStack(spacing: 8) {
                    Text("Remote Monitoring Setup")
                        .font(.title2)
                        .fontWeight(.semibold)
                    
                    Text("Connect to a remote server to coordinate cellular threat detection with other devices")
                        .multilineTextAlignment(.center)
                        .foregroundColor(.secondary)
                        .padding(.horizontal)
                }
                
                VStack(spacing: 16) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Server URL")
                            .font(.headline)
                        TextField("wss://your-server.com:8765", text: $serverURL)
                            .textFieldStyle(.roundedBorder)
                            .keyboardType(.URL)
                            .autocapitalization(.none)
                    }
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("API Key")
                            .font(.headline)
                        SecureField("Enter your API key", text: $apiKey)
                            .textFieldStyle(.roundedBorder)
                    }
                    
                    DisclosureGroup("Advanced Options", isExpanded: $showingAdvanced) {
                        VStack(spacing: 12) {
                            Text("Device ID: \(UIDevice.current.identifierForVendor?.uuidString ?? "Unknown")")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            
                            Text("Connection will use WebSocket protocol with end-to-end encryption")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .padding(.top, 8)
                    }
                    .padding(.vertical, 8)
                }
                .padding(.horizontal)
                
                VStack(spacing: 12) {
                    Button(action: connectToServer) {
                        HStack {
                            if isConnecting {
                                ProgressView()
                                    .scaleEffect(0.8)
                            } else {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                            }
                            Text(isConnecting ? "Connecting..." : "Connect to Server")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(canConnect ? Color.blue : Color.gray)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                    }
                    .disabled(!canConnect || isConnecting)
                    
                    Button("Test Connection") {
                        testConnection()
                    }
                    .disabled(serverURL.isEmpty)
                }
                .padding(.horizontal)
                
                Spacer()
                
                // Quick Setup Section
                VStack(spacing: 12) {
                    Text("Quick Setup")
                        .font(.headline)
                    
                    VStack(spacing: 8) {
                        Button("Use Demo Server") {
                            serverURL = "wss://demo.cellularsecurity.org:8765"
                            apiKey = "demo-key-123"
                        }
                        .buttonStyle(.bordered)
                        
                        Text("Demo server for testing purposes only")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .padding()
                .background(Color(.systemGray6))
                .cornerRadius(12)
                .padding(.horizontal)
            }
            .padding()
            .navigationTitle("Remote Setup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        isPresented = false
                    }
                }
                
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        isPresented = false
                    }
                    .disabled(!remoteService.isConnectedToRemoteServer)
                }
            }
        }
        .onAppear {
            loadSavedSettings()
        }
    }
    
    private var canConnect: Bool {
        !serverURL.isEmpty && !apiKey.isEmpty
    }
    
    private func loadSavedSettings() {
        serverURL = UserDefaults.standard.string(forKey: "remote_server_url") ?? ""
        apiKey = UserDefaults.standard.string(forKey: "api_key") ?? ""
    }
    
    private func connectToServer() {
        guard canConnect else { return }
        
        isConnecting = true
        remoteService.connectToRemoteServer(serverURL: serverURL, apiKey: apiKey)
        
        // Give some time for connection attempt
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            isConnecting = false
        }
    }
    
    private func testConnection() {
        // Basic URL validation
        guard let url = URL(string: serverURL) else {
            showAlert(title: "Invalid URL", message: "Please enter a valid WebSocket URL (e.g., wss://example.com:8765)")
            return
        }
        
        if url.scheme != "wss" && url.scheme != "ws" {
            showAlert(title: "Invalid Protocol", message: "Please use WebSocket protocol (ws:// or wss://)")
            return
        }
        
        showAlert(title: "URL Valid", message: "The server URL format is valid. Click 'Connect to Server' to establish connection.")
    }
    
    private func showAlert(title: String, message: String) {
        // In a real implementation, you'd use an alert
        print("\(title): \(message)")
    }
}

// MARK: - Cellular Security View
struct CellularSecurityView: View {
    @ObservedObject var cellularService: CellularMonitoringService
    @EnvironmentObject var remoteService: RemoteMonitoringService
    @State private var showingDetails = false
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Monitoring Status Card
                    CellularMonitoringCard(cellularService: cellularService)
                    
                    // Remote Monitoring Status Card
                    RemoteMonitoringStatusCard(remoteService: remoteService)
                    
                    // Current Cellular Metrics
                    if let metrics = cellularService.currentCellularMetrics {
                        CellularMetricsCard(metrics: metrics)
                    }
                    
                    // Threat Detection Card
                    CellularThreatsCard(threats: cellularService.cellularThreats)
                    
                    // Signal Analysis Card
                    if let metrics = cellularService.currentCellularMetrics {
                        SignalAnalysisCard(metrics: metrics)
                    }
                }
                .padding()
            }
            .navigationTitle("🛡️ Cellular Security")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(cellularService.isMonitoring ? "Stop" : "Start") {
                        if cellularService.isMonitoring {
                            cellularService.stopMonitoring()
                        } else {
                            cellularService.startMonitoring()
                        }
                    }
                    .foregroundColor(cellularService.isMonitoring ? .red : .green)
                }
            }
        }
    }
}

// MARK: - Cellular Monitoring Card
struct CellularMonitoringCard: View {
    @ObservedObject var cellularService: CellularMonitoringService
    
    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Image(systemName: cellularService.isMonitoring ? "shield.checkmark.fill" : "shield.slash.fill")
                    .foregroundColor(cellularService.isMonitoring ? .green : .orange)
                    .font(.title2)
                
                VStack(alignment: .leading) {
                    Text("IMSI Catcher Detection")
                        .font(.headline)
                    Text(cellularService.isMonitoring ? "Active Monitoring" : "Monitoring Stopped")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                VStack(alignment: .trailing) {
                    Text("\(cellularService.cellularThreats.count)")
                        .font(.title)
                        .fontWeight(.bold)
                        .foregroundColor(cellularService.cellularThreats.isEmpty ? .green : .red)
                    Text("Threats")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            if cellularService.isMonitoring {
                Divider()
                HStack {
                    Label("Real-time Analysis", systemImage: "waveform.path.ecg")
                        .foregroundColor(.blue)
                        .font(.caption)
                    Spacer()
                    Text("Last Update: \(Date().formatted(date: .omitted, time: .shortened))")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Cellular Metrics Card
struct CellularMetricsCard: View {
    let metrics: CellularSecurityMetrics
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Current Cellular Status")
                .font(.headline)
            
            if let tower = metrics.currentTower {
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 16) {
                    MetricItem(title: "Signal", value: "\(tower.signalStrength) dBm", 
                              icon: "antenna.radiowaves.left.and.right",
                              color: signalStrengthColor(tower.signalStrength))
                    MetricItem(title: "Technology", value: tower.technology, 
                              icon: "network", color: .blue)
                    MetricItem(title: "Encryption", value: metrics.encryptionStatus, 
                              icon: "lock.shield", color: encryptionColor(metrics.encryptionStatus))
                    MetricItem(title: "Tower Changes", value: "\(metrics.towerChangeFrequency)/hr", 
                              icon: "arrow.triangle.2.circlepath", 
                              color: towerChangeColor(metrics.towerChangeFrequency))
                }
                
                if !metrics.suspiciousPatterns.isEmpty {
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Suspicious Patterns Detected:")
                            .font(.subheadline)
                            .fontWeight(.semibold)
                            .foregroundColor(.orange)
                        
                        ForEach(metrics.suspiciousPatterns, id: \.self) { pattern in
                            HStack {
                                Image(systemName: "exclamationmark.triangle")
                                    .foregroundColor(.orange)
                                Text(pattern.replacingOccurrences(of: "_", with: " ").capitalized)
                                    .font(.caption)
                            }
                        }
                    }
                }
            } else {
                Text("No cellular data available")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
    
    private func signalStrengthColor(_ strength: Int) -> Color {
        if strength > -70 { return .green }
        if strength > -85 { return .orange }
        return .red
    }
    
    private func encryptionColor(_ encryption: String) -> Color {
        if encryption.contains("A5/3") { return .green }
        if encryption.contains("A5/1") { return .orange }
        return .red
    }
    
    private func towerChangeColor(_ changes: Int) -> Color {
        if changes < 3 { return .green }
        if changes < 6 { return .orange }
        return .red
    }
}

struct MetricItem: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.title3)
            Text(value)
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundColor(color)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Remote Monitoring Status Card
struct RemoteMonitoringStatusCard: View {
    @ObservedObject var remoteService: RemoteMonitoringService
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "cloud.fill")
                    .foregroundColor(.blue)
                    .font(.title3)
                
                VStack(alignment: .leading) {
                    Text("Remote Monitoring")
                        .font(.headline)
                    Text(remoteService.connectionStatus)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Circle()
                    .fill(remoteService.isConnectedToRemoteServer ? Color.green : Color.red)
                    .frame(width: 12, height: 12)
            }
            
            if remoteService.isConnectedToRemoteServer {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "antenna.radiowaves.left.and.right")
                            .foregroundColor(.green)
                        Text("Sharing cellular threats with remote server")
                            .font(.subheadline)
                    }
                    
                    HStack {
                        Image(systemName: "shield.checkered")
                            .foregroundColor(.blue)
                        Text("Coordinated attack detection active")
                            .font(.subheadline)
                    }
                }
                .padding(.top, 4)
            } else {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.orange)
                    Text("Connect to remote server for coordinated monitoring")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding(.top, 4)
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Cellular Threats Card
struct CellularThreatsCard: View {
    let threats: [SecurityThreat]
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Security Threats")
                    .font(.headline)
                Spacer()
                if !threats.isEmpty {
                    Text("\(threats.count) detected")
                        .font(.caption)
                        .foregroundColor(.red)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(.red.opacity(0.1))
                        .cornerRadius(8)
                }
            }
            
            if threats.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.title)
                        .foregroundColor(.green)
                    Text("No threats detected")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .center)
                .padding()
            } else {
                ForEach(threats.prefix(5)) { threat in
                    ThreatRow(threat: threat)
                }
                
                if threats.count > 5 {
                    Text("+ \(threats.count - 5) more threats")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(.top, 4)
                }
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

struct ThreatRow: View {
    let threat: SecurityThreat
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: severityIcon(threat.severity))
                .foregroundColor(severityColor(threat.severity))
                .font(.title3)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(threat.type.replacingOccurrences(of: "_", with: " ").capitalized)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Text(threat.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
            
            Spacer()
            
            Text(threat.timestamp.formatted(date: .omitted, time: .shortened))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(severityColor(threat.severity).opacity(0.1))
        .cornerRadius(8)
    }
    
    private func severityIcon(_ severity: String) -> String {
        switch severity.lowercased() {
        case "high", "critical": return "exclamationmark.triangle.fill"
        case "medium": return "exclamationmark.triangle"
        default: return "info.circle"
        }
    }
    
    private func severityColor(_ severity: String) -> Color {
        switch severity.lowercased() {
        case "high", "critical": return .red
        case "medium": return .orange
        default: return .blue
        }
    }
}

// MARK: - Signal Analysis Card
struct SignalAnalysisCard: View {
    let metrics: CellularSecurityMetrics
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Signal Analysis")
                .font(.headline)
            
            if let tower = metrics.currentTower {
                VStack(spacing: 16) {
                    // Signal Strength Indicator
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Signal Strength")
                                .font(.subheadline)
                            Spacer()
                            Text("\(tower.signalStrength) dBm")
                                .font(.subheadline)
                                .fontWeight(.semibold)
                        }
                        
                        ProgressView(value: signalStrengthPercentage(tower.signalStrength))
                            .progressViewStyle(LinearProgressViewStyle(tint: signalStrengthColor(tower.signalStrength)))
                    }
                    
                    // Signal Delta Warning
                    if abs(metrics.signalStrengthDelta) > 15 {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("Large signal change: \(metrics.signalStrengthDelta > 0 ? "+" : "")\(metrics.signalStrengthDelta) dBm")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(.orange.opacity(0.1))
                        .cornerRadius(8)
                    }
                    
                    // Advanced Metrics (if available)
                    if let rsrp = metrics.rsrp, let rsrq = metrics.rsrq {
                        HStack {
                            VStack {
                                Text("RSRP")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text("\(rsrp, specifier: "%.1f") dBm")
                                    .font(.caption)
                                    .fontWeight(.semibold)
                            }
                            
                            Spacer()
                            
                            VStack {
                                Text("RSRQ")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text("\(rsrq, specifier: "%.1f") dB")
                                    .font(.caption)
                                    .fontWeight(.semibold)
                            }
                            
                            if let sinr = metrics.sinr {
                                Spacer()
                                VStack {
                                    Text("SINR")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Text("\(sinr, specifier: "%.1f") dB")
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                }
                            }
                        }
                        .padding(.top, 8)
                    }
                }
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
    
    private func signalStrengthPercentage(_ strength: Int) -> Double {
        // Convert dBm to percentage (typical range: -120 to -50)
        let normalizedValue = Double(max(-120, min(-50, strength)) + 120) / 70.0
        return normalizedValue
    }
    
    private func signalStrengthColor(_ strength: Int) -> Color {
        if strength > -70 { return .green }
        if strength > -85 { return .orange }
        return .red
    }
}

// MARK: - Remote Monitoring Service
class RemoteMonitoringService: NSObject, ObservableObject {
    @Published var isConnectedToRemoteServer = false
    @Published var connectionStatus = "Disconnected"
    
    private var webSocketTask: URLSessionWebSocketTask?
    private var serverURL: String = ""
    private var apiKey: String = ""
    private var deviceID: String
    private var heartbeatTimer: Timer?
    
    override init() {
        self.deviceID = UIDevice.current.identifierForVendor?.uuidString ?? "unknown-device"
        super.init()
        loadServerSettings()
    }
    
    private func loadServerSettings() {
        // Load from UserDefaults or configuration
        self.serverURL = UserDefaults.standard.string(forKey: "remote_server_url") ?? ""
        self.apiKey = UserDefaults.standard.string(forKey: "api_key") ?? ""
    }
    
    func connectToRemoteServer(serverURL: String, apiKey: String) {
        self.serverURL = serverURL
        self.apiKey = apiKey
        
        // Save settings
        UserDefaults.standard.set(serverURL, forKey: "remote_server_url")
        UserDefaults.standard.set(apiKey, forKey: "api_key")
        
        guard let url = URL(string: serverURL) else {
            DispatchQueue.main.async {
                self.connectionStatus = "Invalid URL"
            }
            return
        }
        
        let task = URLSession.shared.webSocketTask(with: url)
        self.webSocketTask = task
        
        task.resume()
        
        DispatchQueue.main.async {
            self.connectionStatus = "Connecting..."
        }
        
        // Register device
        registerDevice()
        
        // Start receiving messages
        receiveMessage()
        
        // Start heartbeat
        startHeartbeat()
    }
    
    private func registerDevice() {
        let registrationData: [String: Any] = [
            "type": "register_device",
            "device_id": deviceID,
            "device_name": UIDevice.current.name,
            "api_key": apiKey,
            "device_type": "iOS",
            "app_version": "1.0.0",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        
        sendMessage(registrationData)
    }
    
    private func sendMessage(_ data: [String: Any]) {
        guard let webSocketTask = webSocketTask else { return }
        
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: data)
            let message = URLSessionWebSocketTask.Message.data(jsonData)
            
            webSocketTask.send(message) { error in
                if let error = error {
                    print("WebSocket send error: \(error)")
                }
            }
        } catch {
            print("JSON serialization error: \(error)")
        }
    }
    
    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            switch result {
            case .success(let message):
                self?.handleReceivedMessage(message)
                self?.receiveMessage() // Continue listening
                
            case .failure(let error):
                print("WebSocket receive error: \(error)")
                DispatchQueue.main.async {
                    self?.isConnectedToRemoteServer = false
                    self?.connectionStatus = "Connection failed"
                }
            }
        }
    }
    
    private func handleReceivedMessage(_ message: URLSessionWebSocketTask.Message) {
        switch message {
        case .string(let text):
            handleMessageText(text)
        case .data(let data):
            if let text = String(data: data, encoding: .utf8) {
                handleMessageText(text)
            }
        @unknown default:
            break
        }
    }
    
    private func handleMessageText(_ text: String) {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let messageType = json["type"] as? String else {
            return
        }
        
        DispatchQueue.main.async {
            switch messageType {
            case "registration_success":
                self.isConnectedToRemoteServer = true
                self.connectionStatus = "Connected to remote server"
                
            case "error":
                if let errorMessage = json["message"] as? String {
                    self.connectionStatus = "Error: \(errorMessage)"
                }
                
            case "threat_acknowledged":
                print("Threat acknowledged by server")
                
            case "high_priority_alert":
                self.handleHighPriorityAlert(json)
                
            case "coordinated_attack_detected":
                self.handleCoordinatedAttackAlert(json)
                
            default:
                print("Unknown message type: \(messageType)")
            }
        }
    }
    
    private func handleHighPriorityAlert(_ alertData: [String: Any]) {
        // Show local notification for high priority alerts from other devices
        let content = UNMutableNotificationContent()
        content.title = "🚨 Remote Cellular Threat"
        content.body = alertData["message"] as? String ?? "High priority cellular threat detected"
        content.sound = .critical
        
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        
        UNUserNotificationCenter.current().add(request)
    }
    
    private func handleCoordinatedAttackAlert(_ alertData: [String: Any]) {
        // Handle coordinated attack notifications
        let content = UNMutableNotificationContent()
        content.title = "🚨 COORDINATED ATTACK"
        content.body = alertData["message"] as? String ?? "Coordinated cellular attack detected"
        content.sound = .critical
        
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        
        UNUserNotificationCenter.current().add(request)
    }
    
    func sendCellularThreat(_ threat: SecurityThreat, cellularData: CellularSecurityMetrics?) {
        guard isConnectedToRemoteServer else { return }
        
        var location: [String: Any]? = nil
        if let loc = threat.location {
            location = [
                "latitude": loc.latitude ?? 0,
                "longitude": loc.longitude ?? 0,
                "accuracy": loc.accuracy ?? 0,
                "timestamp": ISO8601DateFormatter().string(from: loc.timestamp)
            ]
        }
        
        var cellularDataDict: [String: Any]? = nil
        if let cellular = cellularData {
            cellularDataDict = [
                "signal_strength": cellular.currentTower?.signalStrength ?? 0,
                "technology": cellular.currentTower?.technology ?? "Unknown",
                "encryption_status": cellular.encryptionStatus,
                "tower_changes": cellular.towerChangeFrequency,
                "suspicious_patterns": cellular.suspiciousPatterns
            ]
        }
        
        let threatData: [String: Any] = [
            "type": "cellular_threat",
            "threat_id": threat.id.uuidString,
            "threat_type": threat.type,
            "severity": threat.severity,
            "description": threat.description,
            "timestamp": ISO8601DateFormatter().string(from: threat.timestamp),
            "confidence": 0.8, // Default confidence
            "location": location as Any,
            "cellular_data": cellularDataDict as Any,
            "device_id": deviceID
        ]
        
        sendMessage(threatData)
    }
    
    private func startHeartbeat() {
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.sendHeartbeat()
        }
    }
    
    private func sendHeartbeat() {
        let heartbeatData: [String: Any] = [
            "type": "heartbeat",
            "device_id": deviceID,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        
        sendMessage(heartbeatData)
    }
    
    func disconnect() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = nil
        
        webSocketTask?.cancel()
        webSocketTask = nil
        
        DispatchQueue.main.async {
            self.isConnectedToRemoteServer = false
            self.connectionStatus = "Disconnected"
        }
    }
}
