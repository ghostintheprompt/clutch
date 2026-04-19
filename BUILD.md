# Building Clutch

## Python Backend

### Clone and install

```bash
git clone https://github.com/ghostintheprompt/clutch
cd clutch
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
./quick_start.sh
```

Options:
- `1` — Remote server only (WebSocket coordination server on port 8766)
- `2` — Local monitoring (macOS system_profiler / Linux ModemManager)
- `3` — Complete system test (server + iOS integration)

**First launch:** the server generates and prints an API key. Save it for iOS app setup.

### Docker

```bash
docker build -t clutch .
docker run --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 8766:8766 \
  -v $(pwd)/forensics:/app/forensics \
  clutch
```

`NET_ADMIN` and `NET_RAW` are required for triggered PCAP capture and active IP blocking.

## iOS App

```bash
open iOS-App/NetworkSecurityMonitor.xcodeproj
```

1. Select a physical device target (CoreTelephony does not work on the simulator)
2. Set your Team under Signing & Capabilities
3. `Cmd+R` to build and run

First launch: grant Location Services permission. Then go to **Settings → Remote Monitoring → Setup** to connect to the Python backend.

## Release Archive

```bash
./make_release.sh
```

Creates `clutch-v1.0.0.zip` containing scripts, config files, and docs — ready to attach to a GitHub Release.

## Troubleshooting

**`ModuleNotFoundError`** — activate the venv first: `source venv/bin/activate`

**iOS won't connect to server** — confirm both devices are reachable on the same network; use `ws://` (not `wss://`) unless SSL is configured in `cellular_remote_config.json`

**`tcpdump` permission denied** — outside Docker, run the backend with `sudo` or grant `tcpdump` the `cap_net_raw` file capability

**Xcode signing error** — open the project, go to Signing & Capabilities, and select your personal team
