## Python RAT

### Introduction

This project is a minimal implementation of a Client-Server RAT.

### Install

In order to install the dependencies, you must run the following command: (with or without venv, as you wish)

```bash
pip install -r requirements.txt
```

### Build

#### Linux

As agreed, the linux client will be executed by the python interpreter. So, no build is required. However, you must install the dependencies before.

#### Windows

For Windows client, you must additionally compile the client by running the following command: (`pyinstaller` must be installed in the previous step)

```bash
pyinstaller --noconsole --onefile client.py
```

`--noconsole` means that no window will pop up when the executable is executed.

You must find the executable in the `dist` directory.

### Usage
#### Client

The client don't need any argument to be executed, in order to make quick attacks easier. However, if you want to specify the server IP and port, you can modify those values in the `client.py`, at the end of the file: (`Client` folder)

```python
C2_IP = 'YOUR_IP'
C2_PORT = YOUR_PORT
```

You can run the client by executing the following command:

```bash
python3 client.py
```

#### Server

In order to start the server, you must specify the listening port as the first argument: (`C2` folder)

```bash
python3 main.py YOUR_PORT
```

### Available commands on the server
```
<command> [args]
====================
upload      : Upload a file to selected target | LOCAL_FILE: String   REMOTE_DEST: String | upload payload.exe /tmp/payload.exe
hashdump    : Dump the hashes from the target (may crash on Windows)
search      : Search a file on the target's filesystem 
ipconfig    : Retrieve the IP Configuration from the current target 
shell       : Open a reverse shell from the selected agent (type exit to quit the shell) (not interactive)
screenshot  : Take a screenshot from the selected agent, you can optionally specify a name for the screenshot | Optional: FILE: String | screenshot [my_screenshot]
download    : Download the specified files | FILE: String | Ex: download /etc/passwd /etc/hosts
exit        : Exit the server
agents      : List all connected agents
agent       : Select an agent by ID | ID: Integer | Ex: agent 3
bg          : Deselect the current agent
kill        : Kill an agent by id | ID: Integer | kill 4
help        : Show this help message
exec        : Execute a system command in the local machine
====================
```