from lib import *


if __name__ == "__main__":


    server = Server('0.0.0.0',8015)

    server.start()


    while True:
        command = input("> ")
        if command == "exit":
            exit(0)
        elif command == "agents":
            server.listAgents()
