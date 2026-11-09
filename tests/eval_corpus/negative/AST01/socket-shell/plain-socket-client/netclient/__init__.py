# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import socket


def ping(host="192.0.2.10", port=4444):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(b"ping")
    reply = s.recv(64)
    s.close()
    return reply


def quiet_streams():
    null = open(os.devnull, "w")
    os.dup2(null.fileno(), 1)
