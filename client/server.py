
import socket

def runServer(host, port):

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(host, port)

    while True:
        sleep(1000)
        print("Server is listenig")
