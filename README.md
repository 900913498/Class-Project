# Class-Project
Simple Intrusion Detection System (IDS)
The code I have developed will aim to help utilize a Simple Intrusion Detection System (IDS) using Python to boost security by identifying suspicious activities. The IDS will monitor system logs and analyzing network traffic fast, checking for patterns or any abnormalities that could possibly be a threat. Upon detection of suspicious activity, the system should be able to produce an alert to notify administrators to act and take appropriate action.

My goal was to produce an operative tool that improves security monitoring without requiring complicated setups and costly software. I wanted to build an easy, direct approach to enhance security measures. 

To build a simple Python-based Intrusion Detection System (IDS), you can use libraries like `Scapy` for network traffic monitoring or `watchdog` for monitoring system logs. Below is an example of a basic IDS that monitors network traffic for suspicious activities.

 **How It Works**

1. **Packet Sniffing**:
   - The `sniff` function from Scapy captures network packets in real-time.
   - The `packet_callback` function processes each packet to check for suspicious activity.

2. **Suspicious Activity Detection**:
   - The IDS checks for packets originating from or destined to suspicious IPs.
   - It also monitors for traffic on suspicious ports (e.g., SSH, Telnet, RDP).

3. **Logging Alerts**:
   - Alerts are logged to a file (`alerts.log`) and printed to the console.

4. **Customizable**:
   - You can modify the `suspicious_ips` and `suspicious_ports` lists to match your requirements.

---

### **Running the IDS**
1. Install Scapy if not already installed:
   ```
   pip install scapy
   ```

2. Run the script with administrative privileges:
   - On Windows: Open the terminal as Administrator.
   - On Linux/Mac: Use `sudo`:
     ```
     sudo python Final\ Project.py
     ```

3. Replace `"Wi-Fi"` with your actual network interface name (use `ipconfig` or `ifconfig` to find it).

---

### **Extending the IDS**
- **System Log Monitoring**:
   Use the `watchdog` library to monitor system logs for suspicious entries.
   ```bash
   pip install watchdog
   ```
If `sudo` is disabled on your system, you can still run the script, but you need to ensure it has the necessary permissions to capture network traffic. On Windows, administrative privileges are required to access network interfaces for packet sniffing. Here's how you can proceed:

### **Steps to Run the Script Without `sudo`**
1. **Run as Administrator**:
   - On Windows:
     - Right-click on your terminal (e.g., Command Prompt or PowerShell) and select **"Run as Administrator"**.
     - Navigate to the directory containing your script and run it:
       ```bash
       python "Final Project.py"
       ```

2. **Check Network Interface Name**:
   - Ensure the interface name (`"Wireless LAN adapter Wi-Fi"`) in your script matches your actual network interface.
   - Use the `ipconfig` command in the terminal to list all network interfaces and their names.

3. **Modify Interface Name**:
   - Replace `"Wireless LAN adapter Wi-Fi"` in the script with the correct interface name from `ipconfig`.

---

### **Alternative for Non-Admin Users**
If you cannot run the script with administrative privileges, you can:
1. **Use a Virtual Environment**:
   - Create a virtual environment to isolate the script and its dependencies:
     ```bash
     python -m venv env
     env\Scripts\activate
     pip install scapy
     ```

2. **Capture Traffic on a Specific Port**:
   - Instead of monitoring all traffic, you can capture traffic on a specific port using a tool like `tcpdump` (Linux) or Wireshark (Windows) and analyze the captured packets with your script.

   from scapy.all import sniff, IP, TCP
import logging

# Configure logging to save alerts
logging.basicConfig(filename="alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

from scapy.all import sniff, IP, TCP
import logging

# Configure logging to save alerts
logging.basicConfig(filename="alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

class SimpleIDS:
    def __init__(self, suspicious_ips=None, suspicious_ports=None):
        # Define suspicious IPs and ports
        self.suspicious_ips = ["192.168.1.100", "10.0.0.5", "203.0.113.45", "10.0.0.231"] if suspicious_ips else []
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
