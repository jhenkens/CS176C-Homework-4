__author__ = 'johanhenkens'
import sys, socket, signal,threading, time,os

def signal_handler(signal, frame):
    print '\nGoodbye!'
    sys.exit(0)

def generator(payload, paddlength,wait,total,server,port):
    udpsocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    count = 0
    #figure out how much we wait between each packet
    #setup a lastpacket variable so that we can keep track of when the packet was
    #supposed to be sent, rather than when it was actually sent.
    lastpacket = time.time()

    #rather than keep track of run time, which can have minute miscalculations
    #keep track of packets sent and add a proper wait time between each packet
    while(total>count):
        udpsocket.sendto(payload+bytearray(os.urandom(paddlength)),(server,port))
        lastpacket+=wait
        #sleep until the next packet is supposed to be sent, regardless of when
        #we sent this packet
        count+=1
        temp = lastpacket-time.time()
        time.sleep(temp if temp>0 else 0)

if __name__ == "__main__":
    # setup terminator
    signal.signal(signal.SIGINT,signal_handler)
    #parse inputs
    server_host = sys.argv[1]
    ports=sys.argv[2]
    ports = ports.split("-")
    startport = int(ports[0])
    endport = int(ports[1]) if len(ports)==2 else startport
    [packets_per_second,payload_size_in_bytes,seconds_to_run] = map(int,sys.argv[3:6])
    #setup UDP socket
    udpsocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    #construct payload, padds 'jhenkens' with '*'
    # note: not sure if it should be 'arbitrary data' or 'random data'
    payload2=("jhenkens.")
    paddlength = payload_size_in_bytes-len(payload2)
    paddlength = paddlength if paddlength>0 else 0
    total=packets_per_second*seconds_to_run
    #keep track of how many we have sent
    threads=[]
    wait=1.0/packets_per_second
    for port in range(startport,endport+1) :
        thread = threading.Thread(target=generator,args=[payload2,paddlength,wait,total,server_host,port])
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

