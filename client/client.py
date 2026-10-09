
import sys
import socket

if len(sys.argv) < 2:
    print("Usage: to less arguments")
    sys.exit()

PORT = 53
HOST = sys.argv[1]
COMMAND = sys.argv[2]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(COMMAND.encode())
