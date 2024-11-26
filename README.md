# Network Device Scanner

A Python-based tool to scan and discover network devices on your local network. The script dynamically detects available network adapters, allows you to choose the correct one, and performs a fast ARP-based scan to find active devices and their hostnames.

## Features

- **Dynamic Network Adapter Detection**: Lists all available network adapters and their IP addresses for selection.
- **Concurrent Scanning**: Uses multithreading for fast network scanning.
- **Tabular Output**: Displays discovered devices in a clean table format.
- **Hostname Resolution**: Attempts to resolve the hostname of discovered devices.

## Requirements

- **Python**: Version 3.8 or higher
- **Npcap**: Required for low-level network operations (download and install from [Npcap](https://nmap.org/npcap/)).
- Python Libraries:
  - `scapy`
  - `tabulate`
  - `psutil`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/network-device-scanner.git
   cd network-device-scanner
   ```

2. Install Npcap:
   - Download and install Npcap from [Npcap Official Website](https://nmap.org/npcap/).

3. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the script:
   ```bash
   python network_scanner.py
   ```

2. Select a network adapter from the list:
   ```
   Available Network Adapters:
   [0] Ethernet (192.168.1.100)
   [1] Wi-Fi (192.168.0.101)
   [2] VPN (10.0.0.1)
   Select the network adapter to use (number): 
   ```

3. Wait for the scan to complete. The results will be displayed in a table format:
   ```
   +----------------+------------------------+
   | IP Address     | Device Name            |
   +================+========================+
   | 192.168.0.1    | router.home            |
   | 192.168.0.102  | laptop.local           |
   | 192.168.0.103  | phone.local            |
   +----------------+------------------------+
   ```

## Example Output

```
Available Network Adapters:
[0] Ethernet (192.168.1.100)
[1] Wi-Fi (192.168.0.101)
[2] VPN (10.0.0.1)
Select the network adapter to use (number): 1

Scanning network: 192.168.0.0/24
+----------------+------------------------+
| IP Address     | Device Name            |
+================+========================+
| 192.168.0.1    | router.home            |
| 192.168.0.102  | laptop.local           |
| 192.168.0.103  | phone.local            |
+----------------+------------------------+
```

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for enhancements or bug fixes.

## Disclaimer

This tool is intended for use on your own network. Scanning networks without permission is illegal and unethical. Use responsibly.
