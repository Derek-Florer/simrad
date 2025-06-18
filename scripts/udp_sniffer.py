import socket
import datetime

PORT = 50102
BUFFER_SIZE = 65535

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', PORT))

print(f"Listening for UDP packets on port {PORT}...")

try:
    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        timestamp = datetime.datetime.now().isoformat()
        hexdata = data.hex()
        print(f"[{timestamp}] {addr[0]}:{addr[1]} {len(data)} bytes")
        print(hexdata)
except KeyboardInterrupt:
    pass
finally:
    sock.close()
