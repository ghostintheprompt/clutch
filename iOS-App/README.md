# Clutch — iOS App

Native iOS companion for the Clutch cellular surveillance detector.

Requires a physical iPhone — CoreTelephony does not expose real cellular hardware data on the simulator.

## What It Does

Four-tab interface:

- **Dashboard** — connection status, security overview, current threat level
- **Cellular** — live cellular data collection with real-time threat indicators
- **Alerts** — complete detection history with evidence breakdown
- **Settings** — remote server setup, sensitivity thresholds, notification preferences

Also includes:
- **SIGINT Map** — plots observed towers on a MapKit map, color-coded by threat level, Stingray candidates flagged with a distinct indicator
- **Trust Chain** — inspects TLS certificate chain and DNSSEC posture for a probe endpoint

## Requirements

- iOS 14.0+
- Xcode 14+
- Physical iPhone with cellular connectivity

## Build

```bash
open iOS-App/NetworkSecurityMonitor.xcodeproj
```

1. Select your device target
2. Set your Team under Signing & Capabilities
3. Build and run (`Cmd+R`)

## Connect to the Remote Server

1. Start the Python backend: `./quick_start.sh` → option 1
2. Note the API key printed to the terminal on first run
3. In the iOS app: **Settings → Remote Monitoring → Setup**
4. Enter server URL (`ws://your-server-ip:8766`) and API key
5. Tap **Connect**

Remote sharing is optional. The app runs standalone for local cellular analysis.

## Permissions

- **Location Services** — geo-mapping detected equipment
- **Cellular Data Access** — reading actual cellular hardware state via CoreTelephony

Both are required for full functionality. The app requests them on first launch.
