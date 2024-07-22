import argparse

from server import Server
import sys

SERVER_PORT = 0


def update_server_port(args):
    if args.port < 0 or args.port > 65535:
        print("Port number needs to be between 0 and 65535")
        exit(1)
    global SERVER_PORT
    SERVER_PORT = args.port


def update_global_variables(args):
    update_server_port(args)


def parse_args():
    parser = argparse.ArgumentParser(description='Server for the C2')
    parser.add_argument('--port', help='Server Port (default: 8888)', default=8888, type=int)
    args = parser.parse_args()
    update_global_variables(args)


if __name__ == "__main__":

    parse_args()

    server = Server('0.0.0.0', SERVER_PORT)

    server.start()

    server.main_loop()
