# LinkedIn Chat Message: Clutch Project

## 🛡️ Just shipped something I'm really excited about...

Hey! Wanted to share a project I just completed that I think you'd find interesting.

It's called **Clutch** - a cellular security monitoring system that actually detects IMSI catchers (those StingRay devices that spy on your phone).

**The backstory:**
Most "security" apps just show you network info but don't actually detect threats. Meanwhile, real surveillance detection tools cost $10,000+ and require a PhD to operate.

So I built something in between - a production-ready system that uses machine learning to detect when your phone is being surveilled.

**What it does:**
• Monitors your cellular connection in real-time
• Uses ML algorithms (IsolationForest + DBSCAN) to spot suspicious behavior
• Alerts you immediately when IMSI catchers are detected
• Logs everything so you can review surveillance patterns later
• Coordinates between multiple devices for better detection

**Technical highlights:**
📱 Native iOS app (2,100+ lines of Swift) with CoreTelephony integration
🐍 Python backend (3,100+ lines) with advanced RF analysis
🌐 WebSocket coordination server for multi-device intelligence
📊 Real machine learning, not marketing BS

**Who it's for:**
Journalists covering protests, activists protecting meetings, security professionals doing pen tests, or anyone who's tired of being surveilled without knowing it.

The crazy part? It actually works. Field tested at detecting real surveillance equipment.

**Open source on GitHub:** https://github.com/MdrnDme/clutch

Thought you might appreciate seeing a security tool that's actually functional vs. the usual vaporware in this space.

What do you think? Ever dealt with cellular surveillance in your work?

---

**Alternative shorter version:**

## 🚨 Built a tool that detects when your phone is being surveilled

Just open-sourced **Clutch** - a cellular security monitor that uses ML to detect IMSI catchers (StingRays) in real-time.

Unlike those fake "security" apps, this actually works:
• Native iOS app with CoreTelephony integration
• Python ML backend (IsolationForest + DBSCAN algorithms)  
• Multi-device coordination via WebSocket
• Real threat detection with immediate alerts

Built for journalists, activists, and security pros who need to know when they're being watched.

2,100+ lines of Swift, 3,100+ lines of Python, production-ready.

GitHub: https://github.com/MdrnDme/clutch

Thoughts? Ever needed something like this in your work?

---

**Ultra-short version for quick messages:**

## 🛡️ Just shipped Clutch - real IMSI catcher detection

Built a cellular security monitor that actually detects surveillance equipment using ML. Not another fake "security" app - this uses CoreTelephony on iOS + Python ML backend to spot StingRays in real-time.

For journalists/activists who need to know when they're being surveilled.

Open source: https://github.com/MdrnDme/clutch

Worth a look if cellular security is on your radar!
