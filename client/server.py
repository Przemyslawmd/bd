
import socket
from time import sleep

def runServer(host, port):

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((host, port))

    while True:
        sleep(3)
        print("Server is listenig")
