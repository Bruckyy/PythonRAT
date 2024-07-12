class Agent:
    def __init__(self, conn, sock, id):
        self.ip = conn[0]
        self.port = conn[1]
        self.sock = sock
        self.id = id
        self.hostname = None
        self.user = None
        self.mac = None
        self.uid = None
        self.timestamp = None

    def __str__(self):
        return f"[{self.id}] Agent: {self.ip}:{self.port}"