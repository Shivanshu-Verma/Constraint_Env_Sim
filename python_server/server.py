import socket
import platform

SERVER_NAME = platform.node()          # host machine name
HOST = "0.0.0.0"                        # bind to all interfaces
PORT = 5684                             # change if needed

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"\nServer Name : {SERVER_NAME}")
print(f"Running On  : {HOST}:{PORT}\n")
print("Waiting for pings...\n")

while True:
    data, addr = sock.recvfrom(1024)
    msg = data.decode().strip()

    print(f"Received '{msg}' from {addr}")

    if msg.lower() == "ping":
        sock.sendto(b"pong", addr)
    else:
        sock.sendto(b"unknown", addr)
