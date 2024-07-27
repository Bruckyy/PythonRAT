## Python RAT

### Introduction

This project is a minimal implementation of a Client-Server RAT.

### Install

In order to install the dependencies, you must run the following command: (with or without venv, as you wish)

```bash
pip install -r requirements.txt
```

The server encrypts the communication with the agents. You must generate a private key and a certificate for the server. You can do it by running the following command:

1. Generate the private key:
```bash
openssl genpkey -algorithm RSA -out server.key
```
2. Generate the csr from the private key:
```bash
openssl req -new -key server.key -out server.csr
```
3. Sign the csr with the private key:
```bash
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
```

Please, name the files as `server.key` and `server.crt` and place them in the `C2` directory.

### Build

#### Linux

As agreed, the linux client will be executed by the python interpreter. So, no build is required. However, you must install the dependencies before.

#### Windows

For Windows client, you must additionally compile the client by running the following command: (`pyinstaller` must be installed in the previous step)

```bash
pyinstaller --noconsole --onefile main.py
```

or

```bash
python3 -m PyInstaller --noconsole --onefile main.py
```

`--noconsole` means that no window will pop up when the executable is executed.

You must find the executable in the `dist` directory.

If you got an error, check [this](https://pyinstaller.org/en/stable/installation.html#troubleshooting-missing-pyinstaller-command).

### Usage
#### Client

```
usage: main.py [-h] [-d] [--ip IP] [--port PORT] [--persistence]

Client for the C2

options:
  -h, --help     show this help message and exit
  -d, --debug    Enable debug mode
  --ip IP        Server IP (default: 127.0.0.1)
  --port PORT    Server Port (default: 8888)
  --persistence  Enable persistence
```

You can run the client by executing the following command:

```bash
python3 main.py
```

#### Server

In order to start the server, you must specify the listening port as the first argument: (`C2` folder)

```bash
python3 main.py
```

```
usage: main.py [-h] [--port PORT] [--beat BEAT] [-d]

Server for the C2

options:
  -h, --help   show this help message and exit
  --port PORT  Server Port (default: 8888)
  --beat BEAT  Beat Port (default: 8889
  -d, --debug  Enable debug mode
```

### Available commands on the server
```
<command> [args]
Available Commands:
====================
agents      : List all connected agents
agent       : Select an agent by ID | ID: Integer | Ex: agent 3
bg          : Deselect the current agent
kill        : Kill an agent by id | ID: Integer | kill 4
exec        : Execute a system command in the local machine
help        : Show this help message
exit        : Exit the server
==================== ONCE AGENT SELECTED:
download    : Download the specified files | FILE: String | Ex: download /etc/passwd /etc/hosts
upload      : Upload a file to selected target | FILE: String | upload payload.exe ./payloads/another_payload.exe
search      : Search a file on the target's filesystem 
shell       : Open a reverse shell from the selected agent (type exit to quit the shell) (not interactive)
hashdump    : Dump the hashes from the target (may crash on Windows)
ipconfig    : Retrieve the IP Configuration from the current target 
screenshot  : Take a screenshot from the selected agent, you can optionally specify a name for the screenshot | Optional: FILE: String | screenshot [my_screenshot]
====================
```
/!\ The `download`, `search` and `hashdump` commands can fail on windows clients. /!\

The download command will put downloaded files into the `incoming` directory that it will create.

Commands are base64 encoded over the network between the server and the agents. It will avoid some issues with special characters.

### Misc

### Files structure

```
- C2/
    - main.py: Start the server, should be run with python
    - server.py: Server class, handles the communication with the agents
    - server.key: Private key for the server
    - server.crt: Certificate for the server
    - symbols.py: Custom codes for the communication
    - agent.py: Agent class
- Client/
    - client.py: Client mother class, points to the correct client depending on the OS
    - linuxClient.py: Linux client class
    - windowsClient.py: Windows client class
    - symbols.py: Custom codes for the communication, must be the same as the server. Redundant because of the portability.
```

### Heartbeat

The program got a heartbeat system. One run, agents send frequently a little packet with their ID to the server in order
to keep them alive from the server side.

The client stay alive even if the server is down and the server update its agent table when the client is down.