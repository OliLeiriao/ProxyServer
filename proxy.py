import socket
import threading

SOCKS_VERSION = 1

class Proxy:

    def __init__(self):
        # Authentication for Proxy
        self.username = "username"
        self.password = "password"

    def handle_client(self, connection):
        # Greeting header
        # Read and unpack 2 bytes from a client
        version, nmethods = connection.recv(2)

        # Get available methods [0, 1, 2]
        methods = self.get_available_methods(nmethods, connection)

    def run(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(host,port)
        s.listen()

        while True:
            conn, addr = s. accept()
            print("* New connection from {}".format(addr))

            # Use threads to handle each connection in a seperate thread
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()


    # if not imported as a module, initialize and run
    if __name__ == '__main__':
        proxy = Proxy()
        # Creates a proxy from localhost, on port 3000
        proxy.run("127.0.0.1", 3000)
