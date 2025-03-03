 
import nmap

def discover_devices(network_range):
    """Perform ARP scan to identify active devices on the network."""
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=network_range, arguments='-sn')
        devices = []

        for host in scanner.all_hosts():
            mac_address = scanner[host]['addresses'].get('mac', 'N/A')
            devices.append({'ip': host, 'mac': mac_address})

        return devices
    except Exception as error:
        print(f"Error during device discovery: {error}")
        return []

def scan_ports(target_ip):
    """Perform a quick TCP port scan on the target system."""
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target_ip, arguments='-T4 -F')  # Faster scan with limited ports
        open_ports = scanner[target_ip].all_tcp()

        return open_ports
    except Exception as error:
        print(f"Error during port scanning: {error}")
        return []

def assess_vulnerabilities(target_ip):
    """Perform vulnerability assessment on the target system."""
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target_ip, arguments='-sS -sV -O --script vulners')  # OS detection + vuln scripts
        vulnerabilities = scanner[target_ip].get('tcp', {})

        print("Potential Vulnerabilities:")
        for port, details in vulnerabilities.items():
            service = details.get('name', 'Unknown Service')
            print(f"Port {port}: {service} - {details.get('product', 'No additional info')}")

        return vulnerabilities
    except Exception as error:
        print(f"Error during vulnerability assessment: {error}")
        return {}

if __name__ == "__main__":
    network = input("Enter the network range (e.g., 192.168.1.0/24): ")
    devices = discover_devices(network)
    print(f"Discovered Devices: {devices}")

    target = input("Enter the target IP for port and vulnerability scanning: ")
    open_ports = scan_ports(target)
    print(f"Open Ports on {target}: {open_ports}")

    assess_vulnerabilities(target)
