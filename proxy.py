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

        # Accept only Username/Password authentication
        if 2 not in set(methods):
            # Close connection
            connection.close()
            return

        # Welcome Message
        connection.sendall(bytes([SOCKS_VERSION, 2]))

        # Verify validity of credentials, if invalid do nothing.
        if not self.verify_credentials(connection):
            return

        # Request version == 1
        version, cmd, _, address_type = connection.recv(4)

        if address_type == 1: # If IPv4 address
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3: # If Domain name
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)

    def verify_credentials(self, connection):
        version = ord(connection.recv(1)) # should be 1

        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')

        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')

        # Validate credentials
        if username == self.username and password == self.password:
            # Success status == 0
            response = bytes([version, 0])
            connection.sendall(response)
            return True

        # Else, Failed status != 1
        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return False

    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods
    
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
