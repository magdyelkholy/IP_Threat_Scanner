# 🛡️ IP Threat Scanner v1.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20Mac-green.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License">
  <img src="https://img.shields.io/badge/GUI-CustomTkinter-orange.svg" alt="GUI">
</p>

<p align="center">
  <b>A powerful desktop application to scan IP addresses for threats using VirusTotal & AbuseIPDB APIs</b>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#api-keys">API Keys</a> •
  <a href="#author">Author</a>
</p>

---

## 🔍 Keywords

`IP Scanner` `IP Reputation Checker` `VirusTotal API` `AbuseIPDB API` `Threat Intelligence` `Malware Detection` `SOC Tools` `Security Analyst` `Incident Response` `Blue Team` `IP Lookup` `Bulk IP Scanner` `Cybersecurity` `Network Security` `InfoSec` `Python Security Tool` `Threat Hunting` `IP Blacklist Checker` `Malicious IP Detector` `IP Abuse Checker` `Free IP Scanner` `Open Source Security` `IP Investigation Tool`

---

## ✨ Features

### 🌐 IP Address Support
- **IPv4** addresses (e.g., `8.8.8.8`)
- **IPv6** addresses (e.g., `2001:4860:4860::8888`)
- **Automatic validation** and cleaning of input
- **Private IP detection** - automatically skips non-routable addresses

### 🔑 Multiple API Keys
- Add **unlimited API keys** for each service
- **Automatic rotation** when rate limit is reached
- **Visual indicator** showing current active key
- Never get blocked due to rate limits again!

### 📥 Flexible Input Formats
```
# One per line
8.8.8.8
1.1.1.1

# Comma-separated
8.8.8.8, 1.1.1.1, 9.9.9.9

# JSON array
["8.8.8.8", "1.1.1.1"]

# Mixed with quotes and null values
"95.111.247.139",
null,
"193.142.147.209"
```

### ⏯️ Scan Controls
| Button | Function |
|--------|----------|
| ▶️ Start | Begin scanning IPs |
| ⏸️ Pause | Pause and resume scan |
| ⏹️ Stop | Stop scan immediately |
| 🔄 Reset | Clear all results |

### 🔍 Real-Time Filtering
- Filter by status: **Safe**, **Suspicious**, **Malicious**, **Private**
- **Search** by IP address or country
- Filters work **during scan** - see results as they come!

### 📊 Live Statistics
```
┌─────────────────────────┐
│    📊 Statistics        │
├─────────────────────────┤
│ ✓ Safe              12  │
│ ⚠ Suspicious         3  │
│ ✗ Malicious          2  │
│ 🏠 Private           5  │
├─────────────────────────┤
│ Total               22  │
└─────────────────────────┘
```

### 🌍 Country Information
- Full country names (not just codes)
- Supports **200+ countries**
- Example: `US` → `United States`

### 📤 Export & Quick Actions
- **Export to CSV** with all scan details
- **Open folder** after export
- **Double-click** any IP to open in VirusTotal & AbuseIPDB
- **Right-click menu** for more options
- **Copy IP** to clipboard

### 🎨 Modern UI
- Dark theme with cyan/green/purple accents
- Clean and professional design
- Responsive layout

---

## 🚀 Installation

### Method 1: Quick Start (Windows)

1. Download the latest release
2. Extract the ZIP file
3. Run `install.bat` (first time only)
4. Run `run_scanner.bat`

### Method 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/magdyelkhouly/IP-Threat-Scanner.git
cd IP-Threat-Scanner

# Install dependencies
pip install customtkinter requests

# Run the application
python ip_scanner.py
```

### Method 3: Create Standalone EXE

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
python -m PyInstaller --onefile --windowed --collect-data customtkinter --name "IP_Threat_Scanner" ip_scanner.py

# Find your EXE in dist/ folder
```

Or simply run `build_exe.bat` on Windows!

---

## 🔑 API Keys

### Getting Free API Keys

#### VirusTotal (500 requests/day)
1. Sign up at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Go to Profile → API Key
3. Copy your key

#### AbuseIPDB (1000 requests/day)
1. Sign up at [abuseipdb.com](https://www.abuseipdb.com/register)
2. Go to Account → API
3. Create a new key

### Adding Multiple Keys

💡 **Pro Tip:** Create multiple accounts to get more API keys and avoid rate limits!

1. Click **"⚙️ Manage API Keys"** in the app
2. Click **"➕ Add VT Key"** or **"➕ Add Abuse Key"**
3. Paste your keys
4. Click **"💾 Save All Keys"**

The scanner will automatically rotate between keys when one hits the rate limit.

---

## 📖 Usage

1. **Configure API Keys** - Click "Manage API Keys" and add at least one key
2. **Input IPs** - Type, paste, or load from file (TXT, CSV, JSON)
3. **Start Scan** - Click "🔍 Start Scan"
4. **Monitor Progress** - Watch real-time statistics update
5. **Filter Results** - Click filter buttons to show specific categories
6. **Investigate** - Double-click any IP to open in VirusTotal & AbuseIPDB
7. **Export** - Save results as CSV for reporting

---

## 🔒 Private IP Ranges (Auto-Skipped)

| Type | Range | Example |
|------|-------|---------|
| Private Class A | `10.0.0.0/8` | `10.0.0.1` |
| Private Class B | `172.16.0.0/12` | `172.16.0.1` |
| Private Class C | `192.168.0.0/16` | `192.168.1.1` |
| Loopback | `127.0.0.0/8` | `127.0.0.1` |
| Link-Local | `169.254.0.0/16` | `169.254.1.1` |
| CGNAT | `100.64.0.0/10` | `100.64.0.1` |
| IPv6 Loopback | `::1` | `::1` |
| IPv6 Link-Local | `fe80::/10` | `fe80::1` |
| IPv6 ULA | `fc00::/7` | `fd00::1` |

---

## 📁 Project Structure

```
IP-Threat-Scanner/
├── ip_scanner.py      # Main application
├── requirements.txt   # Python dependencies
├── setup.py           # Package setup
├── install.bat        # Windows installer
├── run_scanner.bat    # Windows launcher
├── build_exe.bat      # Build standalone EXE
├── ip_scanner.spec    # PyInstaller config
├── README.md          # Documentation
└── LICENSE            # MIT License
```

---

## 🛠️ Requirements

- Python 3.8 or higher
- customtkinter >= 5.2.0
- requests >= 2.28.0

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Magdy Elkhouly**

- Security Tool Developer
- Created with ❤️ for the Security Community

---

## ⭐ Support

If you find this tool useful, please consider:
- Giving it a ⭐ **star** on GitHub
- Sharing it with your colleagues
- Reporting bugs or suggesting features

---

## 🔗 Related Links

- [VirusTotal](https://www.virustotal.com/) - Free online virus scanner
- [AbuseIPDB](https://www.abuseipdb.com/) - IP address abuse reports
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern Python UI library

---

## 🏷️ Tags

```
ip-scanner, virustotal, abuseipdb, threat-intelligence, cybersecurity, 
security-tools, ip-reputation, malware-analysis, soc-analyst, 
incident-response, python, desktop-app, gui-application, threat-hunting, 
blue-team, security-automation, ip-lookup, bulk-scanner, network-security, 
infosec, ip-checker, malicious-ip, security-analyst, cyber-defense,
threat-detection, ip-investigation, security-research, osint, 
open-source-intelligence, ip-geolocation, abuse-detection
```

---

<p align="center">
  <b>🛡️ IP Threat Scanner v1.0</b><br>
  Created by Magdy Elkhouly<br>
  Security Tool for Threat Intelligence
</p>
