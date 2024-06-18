import socket
import threading

class Agent:
    
    def __init__(self, conn, sock):
       
        self.ip = conn[0]
        self.port = conn[1]
        self.sock = sock

    def __str__(self):

        return f"[!] Agent: {self.ip}:{self.port}"


class Command:

    def execute(self,command):
        pass

class Server:

    def __init__(self, address, port):
        
        self.address = address
        self.port = port
        self.agents = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    def __str__(self):

        return f"Server: {len(self.agents)} agents connected"


    def addAgent(self, agent:'Agent'):

        self.agents.append(agent)

    def listAgents(self):
        
        for agent in self.agents:
            print(agent)


    def handle_client(self, agent):
        agent.sock.send("caca".encode())
        

    def accept_connections(self):
        while True:
            client_socket, client_address = self.sock.accept()
            agent = Agent(client_address, client_socket)
            print(f"New connection:\n{agent}")
            self.addAgent(agent)
            threading.Thread(target=self.handle_client, args=(agent,)).start()

    def start(self):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.bind((self.address, self.port))
        print(self)
        self.sock = sock
        sock.listen(5)
        threading.Thread(target=self.accept_connections).start()

