from server import Server
import sys

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python3 main.py <port>")
        exit(1)

    try:
        port = int(sys.argv[1])
        if port < 0 or port > 65535:
            print("Port number needs to be between 0 and 65535")
            exit(1)
        
    except ValueError:
        print("Port number needs to be an Integer")
        exit(1)

    server = Server('0.0.0.0',port)

    server.start()

    server.main_loop()