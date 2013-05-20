#!/usr/bin/python

import commands, socket, sys, re

if len(sys.argv) < 3:
    print 'usage: %s [topofile.topo] [machines]' % (sys.argv[0])
    sys.exit(-1)

SERVER_IP = socket.gethostbyname('GS11698.SP.CS.CMU.EDU')
SERVER_PORT = 43278
dir = '/home/cmu_xia/fedora-bin/xia-core/experiments/planetlab/stats/'
my_ip = commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]

out = commands.getoutput(dir + 'ping.py %s %s' % (sys.argv[1], sys.argv[2])).split(";")[2].split(")")[0]
ping = out.split("'")[1]
host = out.split("'")[3]

out = commands.getoutput(dir + 'traceroute.py %s %s' % (sys.argv[1], sys.argv[2]))
hops = re.search(r"\((\d*), 'planetlab1.cs.pitt.edu'\)",out).group(1)

message = 'PyStat:%s;%s;%s;%s' % (my_ip, host, ping, hops)
print message
statSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
statSocket.sendto(message, (SERVER_IP, SERVER_PORT))
if __debug__: print 'Sent packet'
