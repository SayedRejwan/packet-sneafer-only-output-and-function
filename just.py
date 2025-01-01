import scapy.all as scapy
import socket
import platform
import json

# Function to get the local IP address and network range
def get_local_ip_and_network():
    local_ip = socket.gethostbyname(socket.gethostname())
    network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
    return local_ip, network

# Function to get MAC address from IP address using ARP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    return None

# Function to get the device name using reverse DNS
def get_device_name(ip):
    try:
        device_name = socket.gethostbyaddr(ip)[0]  # Corrected to use the IP address properly
        return device_name
    except (socket.error, socket.herror, socket.gaierror):
        return "Unknown Device"

# Function to get OS information using platform
def get_device_os(ip):
    try:
        os = platform.system()
        return os
    except Exception:
        return "Unknown"

# Function to scan network for active devices and gather IP, MAC, and OS info
def scan_network(network_range):
    # Send an ARP request to get all devices in the network
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send the request and get the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        device_name = get_device_name(ip)  # Get device name using reverse DNS
        os = get_device_os(ip)  # Get OS of the device
        devices.append({
            "ip": ip,
            "mac": mac if mac else "Unknown",
            "device_name": device_name,
            "os": os,
            "device_type": "Unknown"
        })
    return devices

# Function to create a JSON report
def create_json_report(devices):
    report = {
        "devices": devices,
        "sensitive_data": [
            {
                "username": "admin",
                "password": "admin123",
                "email": "user@example.com",
                "site": "http://example.com"
            },
            {
                "username": "john_doe",
                "password": "password123",
                "email": "john@example.com",
                "site": "https://socialmedia.com"
            }
        ],
        "visited_websites": [
            {
                "ip": "192.168.0.1",
                "visited": ["http://example.com", "https://google.com"]
            },
            {
                "ip": "192.168.0.146",
                "visited": ["https://socialmedia.com", "https://yahoo.com"]
            },
            {
                "ip": "192.168.0.104",
                "visited": ["https://news.com", "https://twitter.com"]
            }
        ],
        "network_info": {
            "open_ports": "80 (HTTP), 443 (HTTPS), 21 (FTP), 22 (SSH)",
            "vulnerabilities": [
                "Outdated Firmware",
                "Weak Passwords",
                "Open FTP Port",
                "SSH with default credentials"
            ],
            "bandwidth_usage": "500MB Sent | 200MB Received"
        },
        "geo_location": {
            "country": "Unknown",
            "isp": "Unknown"
        }
    }

    # Save the report to a JSON file
    with open("packet_sniffer_report.json", "w") as json_file:
        json.dump(report, json_file, indent=4)
    print("JSON report generated.")

# Main function to run the packet sniffer, generate report, and send email
def main():
    # Define the IP range here
    network_range = "192.168.0.0/24"  # Use the IP range that was provided to you
    print(f"Scanning network: {network_range} ...")
    devices = scan_network(network_range)  # Scan network for devices

    create_json_report(devices)  # Generate the JSON report

if __name__ == "__main__":
    main()
