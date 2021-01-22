#!/usr/bin/env python3

# GeminiGet, aka gg
# USAGE: ./gg path [port]

import os
import socket
import ssl
import urllib.parse
import sys

hostname = 'localhost'
path = sys.argv[1]

port = 1965
if len(sys.argv) > 2:
    port = int(sys.argv[2])

s = socket.create_connection((hostname, port))
context = ssl.SSLContext()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
s = context.wrap_socket(s, server_hostname = hostname)
s.sendall(("gemini://" + hostname + ":" + str(port) + path + "\r\n").encode('UTF-8'))

try:
    fp = s.makefile("rb")
    for line in fp.read().splitlines():
        print(line.decode('UTF-8'))
except:
    pass
