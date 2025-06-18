from scapy.all import sniff, UDP, IP
import socket
import threading

# ========== CONFIG ==========
INTERFACE = "Ethernet"  # Change to your actual network interface name
DEBUG = True
RUNNING = True

TARGET_PORTS = {6678}
TARGET_IPS = {"236.6.7.8", "236.6.7.9", "236.6.7.10", "236.6.7.11"}

# Forwarding configuration so the Java GUI can receive the packets
FORWARD_ADDR = "236.6.7.8"   # Multicast group that the GUI listens on
FORWARD_PORT = 6678
SRC_IP = "169.254.74.24"      # Local interface used to send the packets
SRC_PORT = 38071
_forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
_forward_sock.bind((SRC_IP, SRC_PORT))

# ========== PACKET HANDLER ==========
def packet_callback(packet):
    if not RUNNING:
        return False  # stop sniffing
    if UDP in packet and IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[UDP].dport
        payload = bytes(packet[UDP].payload)

        if dst_ip in TARGET_IPS and dst_port in TARGET_PORTS:
            print(f"[Simrad] {src_ip} → {dst_ip}:{dst_port} | {len(payload)} bytes")
            if DEBUG:
                print(payload.hex(" ", 1))
            # forward the raw payload to the multicast group so the Java GUI can
            # receive and decode the radar data in real time
            _forward_sock.sendto(payload, (FORWARD_ADDR, FORWARD_PORT))

# ========== STOP LISTENER THREAD ==========
def wait_for_enter():
    global RUNNING
    input("🔴 Press Enter to stop sniffing...\n")
    RUNNING = False

# ========== MAIN ==========
if __name__ == "__main__":
    stopper = threading.Thread(target=wait_for_enter)
    stopper.start()

    sniff(iface=INTERFACE, filter="udp", prn=packet_callback, store=0, stop_filter=lambda x: not RUNNING)
    print("✅ Sniffer stopped.")
