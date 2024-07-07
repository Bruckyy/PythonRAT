from server import Server
import sys

if __name__ == "__main__":

    try:
        port = int(sys.argv[1])
        
    except ValueError:
        print("Port number needs to be an Integer")
        exit()

    server = Server('0.0.0.0',port)

    server.start()

    server.main_loop()