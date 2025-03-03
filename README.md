 
# NetworkScanner

A **Python-based network security tool** designed for **network discovery, port scanning, and vulnerability assessment**. 
This tool helps **network administrators and cybersecurity professionals** analyze and secure networks.

## Features

### 🔹 Device Discovery (ARP Scan)
- **Function:** `discover_devices(network_range)`
- **Purpose:** Identifies **active devices** in a network and retrieves their **IP and MAC addresses**.
- **Use Case:** Helps map out all connected devices on a local network.

### 🔹 Port Scanning
- **Function:** `scan_ports(target_ip)`
- **Purpose:** Scans a **target device** for **open TCP ports** to detect possible security risks.
- **Use Case:** Identifies **services running on a system** and potential attack surfaces.

### 🔹 Vulnerability Assessment
- **Function:** `assess_vulnerabilities(target_ip)`
- **Purpose:** Uses **Nmap scripts** to check for **security weaknesses** in the target system.
- **Use Case:** Helps **network security professionals** identify and mitigate vulnerabilities.

## Workflow

1️⃣ **User Input:** Enter a **network range** (e.g., `192.168.1.0/24`) to scan.  
2️⃣ **Device Discovery:** Lists **active devices** in the network.  
3️⃣ **Target Selection:** Choose a device for further scanning.  
4️⃣ **Port Scanning:** Identifies **open ports** on the selected device.  
5️⃣ **Vulnerability Scan:** Detects **security flaws** and **misconfigurations**.  

## Usage

Run the script in a terminal:  
```bash
python Updated_NetworkScanner.py
```

## Dependencies

Ensure you have `nmap` installed:  
```bash
pip install python-nmap
```

## Legal Disclaimer

This tool is intended for **educational and authorized security testing only**. Unauthorized scanning of networks **without permission** is illegal and punishable under law.
