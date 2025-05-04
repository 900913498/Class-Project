from scapy.all import sniff, IP, TCP
import logging

# Configure logging to save alerts
logging.basicConfig(filename="alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

class SimpleIDS:
    def __init__(self, suspicious_ips=None, suspicious_ports=None):
        # Define suspicious IPs and ports
        self.suspicious_ips = ["192.168.1.100", "10.0.0.5", "203.0.113.45", 10.0.0.231"] if suspicious_ips else []
        self.suspicious_ports = suspicious_ports if suspicious_ports else [22, 23, 3389]  # Common ports for SSH, Telnet, RDP

    def packet_callback(self, packet):
        # Check if the packet has IP and TCP layers
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            # Check for suspicious IPs or ports
            if src_ip in self.suspicious_ips or dst_ip in self.suspicious_ips:
                alert = f"Suspicious IP detected: {src_ip} -> {dst_ip}"
                print(alert)
                logging.info(alert)

            if dst_port in self.suspicious_ports:
                alert = f"Suspicious port activity detected: {src_ip} -> {dst_ip}:{dst_port}"
                print(alert)
                logging.info(alert)

    def start_monitoring(self, interface="Wi-Fi"):
        print("Starting network monitoring...")
        sniff(iface=interface, prn=self.packet_callback, store=0)

if __name__ == "__main__":
    # Define suspicious IPs and ports
    suspicious_ips = ["192.168.1.100", "10.0.0.5"]  # Replace with actual suspicious IPs
    suspicious_ports = [22, 23, 3389]  # Common ports for SSH, Telnet, RDP

    # Initialize and start the IDS
    ids = SimpleIDS(suspicious_ips=suspicious_ips, suspicious_ports=suspicious_ports)
    try:
        ids.start_monitoring(interface="Wi-Fi")  # Replace "Wi-Fi" with your network interface
    except KeyboardInterrupt:
        print("Stopping IDS...")
