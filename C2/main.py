from lib import *


if __name__ == "__main__":


    server = Server('0.0.0.0',8011)

    server.start()

    server.main_loop()