# WaveSecure: Wireless Network Scanner & Security Analyser

WaveSecure is a Python-based penetration testing tool designed to assess and strengthen the security of Wi-Fi networks. This tool focuses on Wi-Fi network discovery, Denial-of-Service (DoS) attacks, and the capture of WPA/WPA2 handshakes. By utilizing the power of the Scapy library, WaveSecure automates several critical tasks in wireless network security testing. It allows penetration testers and ethical hackers to scan for available networks, target specific networks with deauthentication attacks, and capture security credentials for further analysis.

## Core Features

### 1. Wi-Fi Network Discovery:
- WaveSecure uses system-level commands to scan for nearby Wi-Fi networks.
- Displays a list of available networks, showing details such as SSID (network name), BSSID (MAC address of the access point), signal strength (in dBm), and channel information.
- Helps users identify the networks in the area that they are targeting or assessing.

### 2. Wireless Interface Selection:
- Allows users to choose which network interface (e.g., `en0`, `wlan0`, etc.) they want to use for further operations.
- Automatically detects the connected networks, if any, and allows users to switch between different interfaces (wired or wireless).

### 3. Deauthentication Attack (DoS):
- Once a target network is selected, WaveSecure performs a **Deauthentication attack** by sending multiple deauthentication packets to the selected network’s access point.
- This attack disrupts the connection between devices and the targeted access point, causing connected clients to lose their connection temporarily.
- This is often used to force a client device to reconnect, which may allow the attacker to capture the WPA/WPA2 handshake needed for cracking the password.

### 4. Packet Sniffing and WPA Handshake Capture:
- After performing the DoS attack, the tool listens for WPA/WPA2 authentication handshakes, which are exchanged when a device connects to a network.
- These handshakes contain the encrypted credentials of the network and can be used for offline brute-force password cracking.
- WaveSecure captures these packets and prepares them for analysis by the attacker, with the goal of discovering the Wi-Fi password.

### 5. User Interface:
- WaveSecure operates via a command-line interface (CLI), making it lightweight and easy to run on multiple systems.
- The tool provides clear prompts to the user, including a list of available networks, instructions for selecting an interface, and options to perform attacks and packet sniffing.
- It also includes basic error handling to ensure smooth execution, with prompts for invalid input and failure scenarios.

## Technologies Used:

- **Python**: The primary programming language for developing the tool. Python’s simplicity and support for libraries like Scapy make it ideal for developing security testing tools.
- **Scapy**: A powerful Python library used for network packet manipulation. Scapy is leveraged to send deauthentication packets, sniff network traffic, and capture WPA handshakes.
- **macOS/Linux/Windows Compatibility**: The tool is designed to work on different operating systems, but specific system commands may vary depending on the platform. The example shown is for macOS, with system commands adjusted accordingly.
- **Subprocess**: This Python module is used to interact with system-level commands (like `airport` on macOS) for scanning networks and querying network interfaces.

## How It Works:

### 1. Scanning for Wi-Fi Networks: 
- The tool initiates a scan using system commands (like `airport` on macOS or `iwlist` on Linux) to retrieve a list of available Wi-Fi networks in the vicinity. It parses the results to extract details such as SSID, BSSID, signal strength, and channel.

### 2. Interface Selection:
- The user is prompted to select a network interface (e.g., `en0` for Wi-Fi on macOS). The tool checks if the selected interface is already connected to a network and displays the status.

### 3. Deauthentication Attack:
- The attacker selects the target network to attack by specifying the SSID and BSSID of the network. 
- WaveSecure then sends deauthentication packets to the target access point, which forces connected clients to disconnect and reconnect. This creates an opportunity to capture the WPA handshake.

### 4. Packet Sniffing:
- As clients reconnect, the tool begins to sniff network traffic, specifically looking for WPA handshakes. These handshakes are captured and stored for potential offline cracking.

### 5. Handshake Analysis:
- The captured WPA handshakes can be used with tools like **Hashcat** or **Aircrack-ng** for offline password cracking attempts.

## Ethical Considerations:
WaveSecure is intended for **ethical hacking** and should only be used on networks that the user owns or has explicit permission to test. Unauthorized attacks on networks without permission are illegal and unethical. The tool is designed to help security professionals identify weaknesses in wireless networks and improve their security posture.

## Possible Use Cases:

- **Penetration Testing**: Security professionals use WaveSecure to test the strength of Wi-Fi security by attempting to capture WPA/WPA2 handshakes and crack the passwords.
- **Wi-Fi Network Security Audits**: Administrators can use the tool to assess the security of their wireless networks by simulating common attacks and identifying potential vulnerabilities.
- **Learning and Research**: Cybersecurity students and researchers can use the tool to study wireless network security, Deauthentication attacks, and WPA cracking techniques.

## Limitations:
- WaveSecure is dependent on the availability of compatible Wi-Fi network interfaces. Not all devices or platforms support packet injection, which is necessary for attacks like Deauthentication.
- The tool requires administrative (root or sudo) privileges to run certain commands and manipulate network traffic.

## Future Improvements:
- Add support for other attack vectors such as **WPS Pin Brute Forcing** and **PMKID Cracking**.
- Incorporate support for more platforms, especially Windows, where certain tools like Scapy’s packet manipulation may have limitations.
- Improve the user interface by adding graphical output or integrating with existing penetration testing frameworks for a more seamless experience.

## Important Disclaimer:
**WaveSecure** is a tool for educational and ethical security testing purposes only. It should be used responsibly and only on networks you have explicit permission to test. Unauthorized use may be illegal and punishable by law.

## Installation

To install and run WaveSecure, follow these steps:

1. Install required dependencies:
   ```bash
   pip install scapy

2. Clone the repository:
   ```bash
   git clone https://github.com/mrvishalkatke/WaveSecure.git

3. Run the script:
   ```bash
   python WaveSecure.py

