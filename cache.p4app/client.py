#!/usr/bin/env python

import sys
import socket
from cache_protocol import *


if len(sys.argv) != 3:
    print("Usage: %s HOST KEY" % sys.argv[0])
    sys.exit(1)

host = sys.argv[1]
key = int(sys.argv[2])

addr = (host, UDP_PORT)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)

# packs key
req = reqHdr.pack(key)
s.sendto(req, addr)

# receives response from server
res, addr2 = s.recvfrom(1024)

# unpacks the server response
key2, valid, value = resHdr.unpack(res)

# checks to see if the server response is valid and equal to the original key
assert key2 == key

if valid:
    print(value)
else:
    print("NOTFOUND")
