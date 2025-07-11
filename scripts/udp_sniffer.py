import socket
import struct
import threading
import time

# === GUI EXPECTS THIS ===
DEST_IPS = ['236.6.7.8']  # OpenBR24 listens on this multicast group
DEST_PORT = 6678         # And this port

SIMRAD_GROUPS = [
    '236.6.7.8', '236.6.7.9', '236.6.7.10',
    '236.6.7.13', '236.6.7.14', '236.6.7.15',
    '236.6.7.19', '236.6.7.20', '236.6.7.21',
    '239.238.55.73'
]

SIMRAD_PORTS = [
    6002, 6003, 6005, 6006, 6678,
    6679, 6680, 6689, 6690,
    6758, 6759, 6768,
    6770, 6771, 6774, 6775
]

packet_counts = {port: 0 for port in SIMRAD_PORTS}
last_timestamps = {port: time.time() for port in SIMRAD_PORTS}
RUNNING = True
sockets = []

# Set to your radar interface IP
INTERFACE_IP = '169.254.187.21'

forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
ttl = struct.pack('b', 1)
forward_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

def bind_and_listen(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(('', port))
    except Exception as e:
        print(f"[ERROR] Failed to bind on port {port}: {e}")
        return

    for group in SIMRAD_GROUPS:
        try:
            mreq = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton(INTERFACE_IP))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            print(f"[SUCCESS] Joined multicast {group}:{port}")
        except Exception as e:
            print(f"[ERROR] Failed to join {group}:{port}: {e}")

    sockets.append(sock)

    def listener():
        while RUNNING:
            try:
                data, _ = sock.recvfrom(65535)
                for ip in DEST_IPS:
                    forward_sock.sendto(data, (ip, DEST_PORT))
                packet_counts[port] += 1
                last_timestamps[port] = time.time()
            except:
                break

    t = threading.Thread(target=listener, daemon=True)
    t.start()

def health_monitor():
    while RUNNING:
        print(f"\n[HEALTH CHECK] Forwarding to:")
        for ip in DEST_IPS:
            print(f"  → {ip}:{DEST_PORT}")
        for port in SIMRAD_PORTS:
            count = packet_counts[port]
            last = time.time() - last_timestamps[port]
            print(f"  ↳ Port {port}: {count} packets | Last {last:.1f}s ago")
        time.sleep(5)

def wait_for_enter():
    global RUNNING
    input("🔴 Press Enter to stop forwarder...\n")
    RUNNING = False
    for sock in sockets:
        sock.close()
    forward_sock.close()
    print("[EXIT] Forwarder exited cleanly.")

if __name__ == "__main__":
    for port in SIMRAD_PORTS:
        bind_and_listen(port)

    monitor = threading.Thread(target=health_monitor)
    stopper = threading.Thread(target=wait_for_enter)
    monitor.start()
    stopper.start()
