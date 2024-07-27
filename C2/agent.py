import datetime

class Agent:
    def __init__(self, conn, sock, id, beat):
        self.ip = conn[0]
        self.port = conn[1]
        self.sock = sock
        self.id = id
        self.hostname = None
        self.user = None
        self.mac = None
        self.uid = None
        self.timestamp = str(datetime.datetime.now())
        self.os = None
        self.listening_beat_port = None
        self.last_beat = beat

    def __str__(self):
        return f"[{self.id}] Agent: {self.ip}:{self.port}"
