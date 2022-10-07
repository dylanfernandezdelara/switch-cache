from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo
import sys
import time

topo = SingleSwitchTopo(2)
N = 2 # should equal the number of hosts in the topology
net = P4Mininet(program='cache.p4', topo=topo)
net.start()

s1, h1, h2 = net.get('s1'), net.get('h1'), net.get('h2')

# TODO Populate IPv4 forwarding table
table_entries = []
for i in range(1, N + 1):
    table_entries.append(dict(
        table_name='MyIngress.ipv4_lpm',
        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % i, 32]},
        action_name='MyIngress.ipv4_forward',
        action_params={'dstAddr': net.get('h%d'%i).intfs[0].MAC(), 'port': i}
        ))

for table_entry in table_entries:
    s1.insertTableEntry(table_entry)

# TODO Populate the cache table
cache_table_entries = []
static_key_value_pairs = [(3, 33)] # option to statically add key-value pairs to the cache
for i in range(len(static_key_value_pairs)):
    cache_table_entries.append(dict(
        table_name='MyIngress.p4_cache',
        match_fields={'hdr.request.key': static_key_value_pairs[i][0]},
        action_name='MyIngress.in_p4_cache_send_msg',
        action_params={'response_value': static_key_value_pairs[i][1]}
        ))

for table_entry in cache_table_entries:
    s1.insertTableEntry(table_entry)

# Now, we can test that everything works

# Start the server with some key-values
server = h1.popen('./server.py 1=11 2=22', stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.4) # wait for the server to be listenning

out = h2.cmd('./client.py 10.0.0.1 1') # expect a resp from server
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 1') # expect a value from switch cache (registers)
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 2') # resp from server
assert out.strip() == "22"
out = h2.cmd('./client.py 10.0.0.1 3') # from switch cache (table)
assert out.strip() == "33"
out = h2.cmd('./client.py 10.0.0.1 123') # resp not found from server
assert out.strip() == "NOTFOUND"

server.terminate()
