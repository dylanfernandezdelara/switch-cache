#!/usr/bin/env python

import sys
import socket
from cache_protocol import *

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', UDP_PORT))

store = {1: 11, 2: 22}

# Load some key/values from args, e.g. ./server.py 1=11 3=123
for arg in sys.argv[1:]:
    k,v = map(int, arg.split('='))
    store[k] = v

# server runs forever
while True:
    # receives from port 1024
    req, addr = s.recvfrom(1024)
    key, = reqHdr.unpack(req)

    # address requesting key X
    print(addr, "-> Req(%d),"%key)

    # if key is in store, send back the value
    if key in store:
        valid, value = 1, store[key]
        print("<- Res(%d)" % value)
    else:
        valid, value = 0, 0
        print("<- Res(NOTFOUND)")

    # pack the response and send it back to the client
    res = resHdr.pack(key, valid, value)
    s.sendto(res, addr)

