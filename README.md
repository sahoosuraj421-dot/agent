# 🛡️ Firewall File Downloader & Security Audit Agent

A Streamlit web application and CLI agent to scan target IPs/subnets, verify reachability, authenticate via firewall gateways, download firewall configuration files (`.json` and `.cfg`), and generate comprehensive security audit reports.

---

## 🚀 Running the Streamlit UI

You can start the web interface using either:

### Method 1: Command Line
```powershell
python -m streamlit run app.py
```

### Method 2: One-Click Launcher
Double-click `run_ui.bat` in this folder.

The UI will automatically open in your default browser at `http://localhost:8501`.

---

## ✨ Features

1. **Target Definition & Reachability Scanning**:
   - Scan single IP addresses (e.g. `127.0.0.1`, `192.168.1.1`) or subnets (e.g. `192.168.14.0/24`).
   - Quick preset buttons for instant test selection.
   - Live socket probe and Nmap reachability verification.
   - Discovered host picker when scanning subnets.

2. **Secure Authenticated Gateway**:
   - Masked password and API token input.
   - Built-in Simulation / Demo Mode for immediate testing without physical hardware.
   - Multi-vendor support: Fortinet FortiGate, Palo Alto PAN-OS, Cisco RESTCONF, or Auto-Detect.

3. **Firewall Policy & Interface Inspection**:
   - Interactive, searchable data tables for firewall security rules (Accept / Deny, Source, Destination, Service).
   - Network interfaces status table (WAN, LAN, DMZ, allowed management services).
   - Firewall system status (Hostname, Serial, Firmware Version, Uptime).

4. **Security Audit Reports & Downloads**:
   - 1-click downloads for JSON configuration files and plain text `.cfg` files.
   - Download Markdown (`.md`) and JSON (`.json`) security audit reports.

5. **Backup & History Explorer**:
   - Browse and preview previously downloaded configurations and audit reports.
