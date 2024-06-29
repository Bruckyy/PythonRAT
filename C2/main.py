from lib import *
import sys

if __name__ == "__main__":


    server = Server('0.0.0.0',int(sys.argv[1]))

    server.start()

    server.main_loop()