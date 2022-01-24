#!/usr/bin/env python3

import socket
import random
import time

with open('hamlet.txt', 'r') as hf:
    hamlet = hf.read()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('0.0.0.0', 501))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f'Connection: {addr}')
        time.sleep(1)

        conn.sendall(b'GRAVEDIGGER\r\n')
        conn.sendall(b'What do you call a person who builds stronger things than a stonemason, a shipbuilder, or a carpenter does?\r\n')

        while True:
            conn.sendall(b'PENTESTER\r\n')

            data = conn.recv(1024)

            if b'gallows' in data:
                conn.sendall(b"THM{REDACTED}\r\n")
                break
            else:
                start = random.randint(0, len(hamlet) - 100)
                end = start + random.randint(1, 100)
                conn.sendall(hamlet[start:end].strip().encode('utf-8'))
                conn.sendall(b'\r\n')

            if not data:
                break
