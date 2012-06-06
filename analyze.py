import dpkt
import Gnuplot
import sys
import socket 
import operator
VERBOSE = False

# This program uses the python libray dpkt to parse PCAP files.
# dpkt is written in python, and the source code for each class 
# (check the "Source" tab! on the site) is very easy to read
# and provides all the information about methods and class
# members. A popular alternative is scapy.
# Get it at http://code.google.com/p/dpkt/ .

# This program uses the Gnuplot.py python library. The function
# graphThis(x_data, x_label, y_data, y_label, title, outputFileName)
# Will generate a graph using Gnuplot. You must have both
# Gnuplot.py and Gnuplot installed to use this!

# ip.p values from http://www.iana.org/assignments/protocol-numbers/
# IPv4: 4 TCP:6 UDP:17


# If VERBOSE = True, displays all DNS queries and responses.
# Always  provides statistics about the number of requests
# This could be easily modified to instead provide other
# statistics, such as size, packets per second, bytes per second
# etc, and to work with other protocols than DNS.
def dumpDNS(pcap):
   cnames = 0
   requests = 0
   pointers = 0
   for timestamp, buf in pcap:
      try: eth = dpkt.ethernet.Ethernet(buf)
      except: continue
      if eth.type != 2048: continue
      # make sure we are dealing with UDP
      # ref: http://www.iana.org/assignments/protocol-numbers/
      try: ip = eth.data
      except: continue
      if ip.p != 17: continue # Per RFC5237
      try: udp = ip.data
      except: continue
      if udp.sport != 53 and udp.dport != 53: continue
      try: dns = dpkt.dns.DNS(udp.data)
      except: continue
      if dns.qr != dpkt.dns.DNS_R: continue
      if dns.opcode != dpkt.dns.DNS_QUERY: continue
      if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
      if len(dns.an) < 1: continue
      for answer in dns.an:
         if answer.type == 5:
            if VERBOSE:
               print "CNAME request" + answer.name
            cnames += 1
         elif answer.type == 1:
            if VERBOSE:
               print "A request: " + socket.inet_ntoa(answer.rdata)
            requests += 1
         elif answer.type == 12:
            if VERBOSE:
               print "PTR request", answer.name, "\tresponse", answer.ptrname
            pointers += 1
   print str(cnames) + " CNAME requests"
   print str(requests) + " A requests"
   print str(pointers) + " PTR requests"

   # Measure variation in round trip time for DNS
   # For each dns request/response pair, determine
   # instantaneous packet delay variation. Also
   # Calculate average and standard deviation.
def dnsJitter(pcap):

   # Do so by creating maps of {id=timeSent} and {id=timeRecv}
   requested = {}
   responses = {}
   rttMap = {}
   for timestamp, buf in pcap:
      # the try [something]: continue clauses server to filter
      # out packets that don't match our requirements.
      eth = dpkt.ethernet.Ethernet(buf)
      ip = eth.data
      try:
         udp = ip.data
      except:
         continue
      try:
         dns = dpkt.dns.DNS(udp.data)
      except:
         continue

      # At this point we know the packet is a DNS packet.
      # And any code we write here will be applied to all
      # DNS packets in the pcap file.
      if isRequest(dns):
         requested[dns.id] = timestamp
      if isResponse(dns):
         responses[dns.id] = timestamp

   print "Responses: " + str(responses)
   print "Requested: " + str(requested)
   # We can easily generate the RTT for each DNS communication
   # because the request and response have the same random ID.
   for uuid, time in requested.iteritems():
      if uuid in responses.keys():
         rttMap[uuid] = responses[uuid] - requested[uuid]

   if VERBOSE:
      print rttMap
   # Sort the requests in order of time sent.
   ordered_rttMap = sorted(requested.iteritems(), key=operator.itemgetter(1))
   
   last_rtt = None
   # Storing results in python Lists (or Arrays) allows them to be passed
   # to GNUplot as data columns.
   timestamps = []
   variation = []
   # Iterating over a map like this gives us both keys and values
   # We really only need the uuid, we instead could use 
   # for uuid in ordered_rttMap.keys():
   for (uuid, requestTime) in ordered_rttMap: # SORTED REQUESTS
      # For each packet, add the time it was sent to timestamps
      # and add the difference in RTT between it and its predecessor
      # to variation. Since we do this for each packet, timestamp[i]
      # and variation[i] are from the same packet.
      # 
      if uuid in rttMap:
         timestamps.append(requested[uuid])
         if last_rtt == None:
            variation.append(0)
         else:
            # uuid is ordered by time of transmission
            variation.append(rttMap[uuid] - last_rtt)
         last_rtt=rttMap[uuid]
      
   # Great, now we can display timestamps and variation on a graph!
   # Note that you can do much better stylistically with GNUplot
   # than you can with this function! In terms of size and position
   # of graph elements.
   graphThis(timestamps, "Time", variation, "Variation (ms)","Instantaneous packet delay variation", "jitter.png")
   
   # Calculate some statistics
   mean, std = meanstdv(variation)
   print "Average instantaneous delay variation (aka jitter): " + str(mean)
   print "Standard deviation " + str(std)

"""
From William Park (Rutgers)
Calculate mean and standard deviation of data x[]:
    mean = {\sum_i x_i \over n}
    std = sqrt(\sum_i (x_i - mean)^2 \over n-1)
"""
def meanstdv(x):
    from math import sqrt
    n, mean, std = len(x), 0, 0
    for a in x:
	mean = mean + a
    mean = mean / float(n)
    for a in x:
	std = std + (a - mean)**2
    std = sqrt(std / float(n-1))
    return mean, std

def isRequest(dns):
   if dns.qr != dpkt.dns.DNS_Q:
      return False
   if dns.opcode != dpkt.dns.DNS_QUERY:
      return False
   if len(dns.qd) != 1:
      return False
   if len(dns.an) != 0:
      return False
   if len(dns.ns) != 0:
      return False
   if dns.qd[0].cls != dpkt.dns.DNS_IN:
      return False
   if dns.qd[0].type != dpkt.dns.DNS_A:
      return False
   return True

def isResponse(dns):
   if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
      return False
   if dns.qr != dpkt.dns.DNS_R:
      return False
   if len(dns.an) < 1:
      return False
   return True

#graphThis(timestamps, "Time", variation, "Variation (ms)","Instantaneous packet delay variation", "jitter.png")

# 
def graphThis(x_data, x_label, y_data, y_label, title, outputFileName):
   g = Gnuplot.Gnuplot() 
   print "Sanity Check: "
   print "len("+ x_label + ")="+str(len(x_data))
   print "len("+ y_label + ")="+str(len(y_data))
   print "Graphing " + x_label + " vs " + y_label
   if VERBOSE==True:  
      print(x_data)
      print("Printing " + y_label)
      print(y_data)
   # Create a Data object from our arguments.
   # It is possible to have multiple data
   # Objects on one Gnuplot graph.
   d = Gnuplot.Data(x_data,y_data,title=title)

   # To use any thing you would enter at the 
   # GNUplot interpreter, use this format:
   g('set grid')
   g('set style data lines')
   # Or you can access properties directly like:
   g.xlabel(x_label)
   g.ylabel(y_label)
   g.title(title)

   # Now that we have a basic graph, plot our data.
   g.plot(d)
   # And output to PNG.
   g.hardcopy(outputFileName,terminal = 'png')
   g.reset()



def reduceToRTPPort(list):
    resultList = []
    for timestamp, buf in list:
        try: eth = dpkt.ethernet.Ethernet(buf)
        except: continue
        if eth.type != 2048: continue
        try: ip = eth.data
        except: continue
        if ip.p != 17: continue # if not UDP, continue
        try: udp = ip.data
        except: continue
        if udp.dport != 10080: continue
        resultList.append((timestamp,udp))



    cnames = 0
    requests = 0
    pointers = 0
    for timestamp, buf in pcap:
        try: eth = dpkt.ethernet.Ethernet(buf)
        except: continue
        if eth.type != 2048: continue
        # make sure we are dealing with UDP
        # ref: http://www.iana.org/assignments/protocol-numbers/
        try: ip = eth.data
        except: continue
        if ip.p != 17: continue # Per RFC5237
        try: udp = ip.data
        except: continue
        if udp.sport != 53 and udp.dport != 53: continue
        try: dns = dpkt.dns.DNS(udp.data)
        except: continue
        if dns.qr != dpkt.dns.DNS_R: continue
        if dns.opcode != dpkt.dns.DNS_QUERY: continue
        if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
        if len(dns.an) < 1: continue
        for answer in dns.an:
            if answer.type == 5:
                if VERBOSE:
                    print "CNAME request" + answer.name
                cnames += 1
            elif answer.type == 1:
                if VERBOSE:
                    print "A request: " + socket.inet_ntoa(answer.rdata)
                requests += 1
            elif answer.type == 12:
                if VERBOSE:
                    print "PTR request", answer.name, "\tresponse", answer.ptrname
                pointers += 1
    print str(cnames) + " CNAME requests"
    print str(requests) + " A requests"
    print str(pointers) + " PTR requests"


if __name__=="__main__":
# Open the pcap file passed as the command line argument
    if len(sys.argv) !=3:
        print "Usage:\n", sys.argv[0], "dependent_variable pcap_file_list.txt"
        print "pcap_file_list.txt has, on alternating lines, the pcap and the corresponding dependent variable value"
        sys.exit()
    f = open(sys.argv[2])

    pcap = dpkt.pcap.Reader(f)
    trimmed = reduceToRTPPort(pcap)
    print len(trimmed)


#Run our functions and close the pcap file.
#dumpDNS(pcap)
#dnsJitter(pcap)
#f.close()
