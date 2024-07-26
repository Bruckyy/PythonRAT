import argparse

from server import Server
import sys

SERVER_PORT = 0
BEAT_PORT = 0
DEBUG_MODE = False


def is_port_in_range(port):
    return 0 < port < 65536

def check_if_port_in_range(port):
    if not is_port_in_range(port):
        print("Port number needs to be between 0 and 65535")
        exit(1)


def update_server_port(args):
    check_if_port_in_range(args.port)
    global SERVER_PORT
    SERVER_PORT = args.port


def update_beat_port(args):
    check_if_port_in_range(args.beat)
    global BEAT_PORT
    BEAT_PORT = args.beat

def update_debug_mode(args):
    global DEBUG_MODE
    DEBUG_MODE = args.debug


def update_global_variables(args):
    update_server_port(args)
    update_beat_port(args)
    update_debug_mode(args)


def parse_args():
    parser = argparse.ArgumentParser(description='Server for the C2')
    parser.add_argument('--port', help='Server Port (default: 8888)', default=8888, type=int)
    parser.add_argument('--beat', help='Beat Port (default: 8889', default=8889, type=int)
    parser.add_argument('-d', '--debug', help='Enable debug mode', default=False, action='store_true')
    args = parser.parse_args()
    update_global_variables(args)


if __name__ == "__main__":

    parse_args()

    server = Server('0.0.0.0', SERVER_PORT, BEAT_PORT, DEBUG_MODE)

    server.start()

    server.main_loop()
