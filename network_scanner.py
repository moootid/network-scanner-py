import socket
import ipaddress
import psutil
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
from mac_vendor_lookup import MacLookup

def get_device_name(ip):
    """
    Attempt to resolve the hostname for the given IP.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_mac_vendor(mac):
    """
    Lookup manufacturer/vendor for a given MAC address.
    """
    try:
        return MacLookup().lookup(mac)
    except Exception:
        return "Unknown"

def list_network_adapters():
    """
    List available network adapters and their IP addresses.
    """
    adapters = []
    interfaces = psutil.net_if_addrs()
    for adapter_name, addresses in interfaces.items():
        for addr in addresses:
            if addr.family == socket.AF_INET:  # IPv4 address
                adapters.append({"name": adapter_name, "ip": addr.address})
    return adapters

def choose_network_adapter(adapters):
    """
    Allow the user to select a network adapter from the list.
    """
    print("\nAvailable Network Adapters:")
    for i, adapter in enumerate(adapters):
        print(f"[{i}] {adapter['name']} ({adapter['ip']})")
    while True:
        try:
            choice = int(input("Select the network adapter to use (number): "))
            if 0 <= choice < len(adapters):
                return adapters[choice]
            else:
                print("Invalid choice. Please select a valid adapter number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def get_network_from_adapter(adapter):
    """
    Derive the network range from the selected adapter's IP address.
    """
    ip = adapter["ip"]
    subnet = "255.255.255.0"  # Assuming /24 subnet mask
    network = ipaddress.IPv4Network(f"{ip}/{subnet}", strict=False)
    return str(network)

def scan_ip(ip, iface):
    """
    Send an ARP request to a single IP and return the result if the host is reachable.
    """
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered = srp(packet, iface=iface, timeout=1, verbose=False)[0]

        if answered:
            for _, received in answered:
                device = {
                    "IP Address": received.psrc,
                    "MAC Address": received.hwsrc,
                    "Device Name": get_device_name(received.psrc),
                    "Manufacturer": get_mac_vendor(received.hwsrc),
                }
                return device
    except Exception as e:
        # You might want to log the exception e for debugging
        pass
    return None


def discover_devices_concurrent(network, iface):
    """
    Perform a concurrent ARP scan across the network.
    """
    ip_list = [str(ip) for ip in ipaddress.IPv4Network(network, strict=False).hosts()]
    devices = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(scan_ip, ip, iface): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                devices.append(result)

    return devices


def main():
    """
    Main function to run the network scanner.
    """
    # List network adapters and choose one
    adapters = list_network_adapters()
    if not adapters:
        print("No network adapters with IPv4 addresses found.")
        return

    selected_adapter = choose_network_adapter(adapters)
    network = get_network_from_adapter(selected_adapter)

    print(f"\nScanning network: {network}")
    devices = discover_devices_concurrent(network, selected_adapter['name'])

    if devices:
        print(tabulate(devices, headers="keys", tablefmt="grid"))
    else:
        print("No devices found on the network.")


if __name__ == "__main__":
    main()