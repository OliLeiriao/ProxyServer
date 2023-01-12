import socket
import threading
import select

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

        # Convert bytes to unsigned short array
        port = int.from_bytes(connection.recv(2), 'big', signed=False)

        try:
            if cmd == 1: # Connect
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                print("* Connected to {}:{}".format(address, port))
            else:
                connection.close()

            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
            port = bind_address[1]

            # Connection reply for client
            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')
            ])
        
        except Exception as e:
            # Connection refused error in case of rejection
            reply = self.generate_failed_reply(address_type, 5)

        connection.sendall(reply)

        # Establish data exchange
        if reply[1] == 0 and cmd == 1:
            # Loops while connected
            self.exchange_loop(connection, remote)

        # Finally, closes connection
        connection.close()

    
    def exchange_loop(self, client, remote):
        # Wait until client or remote is available for read
        while True:
            r, w, e = select.select([client, remote], )

            if client in r:
                # If the client's socket is readable, then read 4 KB and send it to the remote
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break



    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

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
