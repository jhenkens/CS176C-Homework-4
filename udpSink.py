from socket import *
import time
import string

host = "0.0.0.0"
port = 4567
buffer = 102400
# Create socket and bind to address
UDPSock = socket(AF_INET,SOCK_DGRAM)
UDPSock.bind((host,port))

print "\nServer bound to port " + str(port)

while 1:
	data,addr = UDPSock.recvfrom(buffer)
	if not data:
		print "Empty packet."
	else:
		dataAmount = len(data)
		words = string.split(data,".",1)
		if len(words) > 0:
			print "Received UDP packet of size " + str(dataAmount) + " from student " + words[0] + " at IP " + str(addr)
		else:
			print "Received UDP packet of size " + str(dataAmount)
			
UDPSock.close()