# 📱 Network Security Monitor - "Bi-Curious" iOS Companion App

A beautiful iOS companion app that creates a **bi-directional monitoring network** between your Mac and iPhone. This "bi-curious" app doesn't just receive alerts - it actively participates in network security monitoring by contributing iPhone network intelligence back to your Mac.

## ✨ Bi-Directional Features

### 📡 **Two-Way Network Intelligence**
- **Mac → iPhone**: Receive real-time security alerts from your Mac's network monitoring
- **iPhone → Mac**: Send iPhone network activity, app connections, and cellular/WiFi status to Mac
- **Cross-Device Correlation**: Identify suspicious patterns across both devices
- **Unified Security Dashboard**: See combined network activity from Mac and iPhone

### 🔄 **Bi-Curious Monitoring Capabilities**
- **🔄 Real-time Bi-Directional Connection**: WebSocket connection enabling two-way data flow
- **📊 Dual-Device Dashboard**: Monitor both Mac and iPhone network activity simultaneously  
- **🚨 Cross-Platform Alerts**: Security threats detected on either device alert both
- **📱 Mobile Network Intelligence**: iPhone cellular and WiFi data enhances Mac security
- **⚙️ Synchronized Configuration**: Settings and rules sync between devices
- **🎨 Native iOS Design**: Follows Apple's Human Interface Guidelines

### 🌐 **What Makes It "Bi-Curious"**
- **Curious About Both Networks**: Monitors both Mac's wired/WiFi and iPhone's cellular/WiFi
- **Curious About Cross-Device Patterns**: Detects coordinated attacks across devices
- **Curious About Mobile Threats**: iPhone contributes mobile-specific threat intelligence
- **Curious About Location Context**: iPhone GPS data adds location context to security events

## 🚀 Quick Setup

### Prerequisites
- iOS 15.0 or later
- Xcode 13.0 or later (for building)
- Mac running the Network Security Monitor
- Both devices on the same network

### Building the App

1. **Open Xcode**:
   ```bash
   open NetworkSecurityMonitor.xcodeproj
   ```

2. **Configure Bundle Identifier**:
   - Select the project in Xcode
   - Go to "Signing & Capabilities"
   - Change the Bundle Identifier to something unique (e.g., `com.yourname.networksecuritymonitor`)

3. **Build and Run**:
   - Select your device or simulator
   - Press `Cmd+R` to build and run

### Connecting to Your Mac

1. **Start the Mac Server**:
   ```bash
   ./setup_ios.sh
   ```

2. **Get Your Mac's IP Address**:
   - The setup script will display your Mac's IP address
   - Or find it in System Preferences → Network

3. **Connect the iPhone App**:
   - Open the app on your iPhone
   - Tap "Connect" in the dashboard
   - Enter your Mac's IP address
   - Tap "Connect"

## 📋 App Screens & Bi-Directional Features

### 🏠 Bi-Directional Dashboard
- **Connection Status**: Shows two-way connection status between Mac and iPhone
- **Mac Statistics**: Real-time network monitoring stats from your Mac
- **iPhone Statistics**: Network activity from your iPhone (cellular, WiFi, apps)
- **Cross-Device Alerts**: Security alerts from both devices
- **Unified Threat Level**: Combined security status across both devices
- **Quick Actions**: Scan networks, sync configurations, export cross-device logs

### 🚨 Cross-Platform Alerts
- **All Alerts**: Complete list of security notifications from Mac and iPhone
- **Device Source Filter**: Filter by Mac alerts, iPhone alerts, or cross-device correlations
- **Alert Types**: 
  - Mac network events (new devices, connections, suspicious activity, malware)
  - iPhone network events (app connections, cellular changes, suspicious apps)
  - Cross-device patterns (coordinated attacks, device fingerprinting attempts)
- **Bi-Directional Response**: Take action on alerts from either device
- **Smart Correlation**: Automatically links related events across devices

### ⚙️ Synchronized Settings
- **Connection Management**: Manage bi-directional connection with automatic failover
- **Monitoring Preferences**: Configure what iPhone data to share with Mac
- **Privacy Controls**: Fine-tune what mobile data is shared (apps, location, usage)
- **Alert Synchronization**: Sync alert rules and thresholds between devices
- **Cross-Device Backup**: Settings and configurations backed up across devices
- **About**: App version and bi-directional monitoring status

## 🔧 Alert Types

The app receives four types of security alerts:

| Type | Icon | Description |
|------|------|-------------|
| **New Device** | 📱 | A new device connected to your network |
| **New Connection** | 🌐 | A new network connection was detected |
| **Suspicious Activity** | ⚠️ | Unusual network patterns detected |
| **Potential Malware** | 🚨 | Possible malware communication detected |

## 🌐 Network Configuration

### WebSocket Connection
- **Default Port**: 8765
- **Protocol**: WebSocket (ws://)
- **Format**: JSON messages
- **Auto-reconnect**: Yes

### Message Format
The app expects JSON messages in this format:

```json
{
  "id": "unique-alert-id",
  "timestamp": "2025-06-11T10:30:00Z",
  "type": "newDevice",
  "message": "New device connected: 192.168.1.15",
  "deviceIP": "192.168.1.15",
  "processName": null
}
```

## 🔒 Security & Privacy

- **Local Network Only**: All communication stays on your local network
- **No Cloud Data**: No data is sent to external servers
- **Encrypted Notifications**: Push notifications use Apple's secure delivery
- **Permission-Based**: Requires explicit notification permissions

## 🛠️ Troubleshooting

### Connection Issues
1. **Check Network**: Ensure both devices are on the same Wi-Fi network
2. **Verify IP Address**: Make sure you're using the correct Mac IP
3. **Firewall Settings**: Check Mac firewall allows connections on port 8765
4. **Restart Server**: Stop and restart the Mac WebSocket server

### No Notifications
1. **Check Permissions**: Go to iOS Settings → NetworkSecurityMonitor → Notifications
2. **Test Notification**: Use "Test Notification" in app settings
3. **Background Refresh**: Enable in iOS Settings → General → Background App Refresh

### Build Issues
1. **Update Xcode**: Ensure you have the latest Xcode version
2. **Clean Build**: Product → Clean Build Folder in Xcode
3. **Simulator Issues**: Try a different simulator or real device

## 📱 System Requirements

- **iOS**: 15.0 or later
- **Devices**: iPhone, iPad
- **Network**: Wi-Fi connection
- **Storage**: ~10MB

## 🎯 Development

### Architecture
- **SwiftUI**: Modern declarative UI framework
- **Combine**: Reactive programming for data flow
- **UserNotifications**: Native iOS push notifications
- **Network**: WebSocket communication

### Key Components
- `NetworkMonitorService`: Handles WebSocket connection and data
- `ContentView`: Main tab-based interface
- `DashboardView`: Overview and status display
- `AlertsView`: Alert management and filtering
- `SettingsView`: Configuration and preferences

## 📄 License

This project is part of the Network Security Monitor suite.

## 🤝 Support

For issues and questions:
1. Check the troubleshooting section above
2. Verify your Mac server is running correctly
3. Ensure network connectivity between devices

---

**Happy Monitoring! 🛡️📱**
