#!/usr/bin/env python3.12

import sys
import signal
import argparse
import socket
import dnslib
import base64
from dpkt import dns

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

        # Setup a UDP server listening on port UDP 53
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        IP = "0.0.0.0"
        PORT = 53
        self.sock.bind((IP, PORT))

        while True:
            try:
                data, address = self.sock.recvfrom(65536)
                query = dnslib.DNSRecord.parse(data)
                
                self.dns_query_handler(query, address)                

            except dnslib.DNSError as e:
                print(f"DNSLib error: {e}")
                continue
            except Exception as e:
                print(f"An error occurred: {e}")
                break
    
    def dns_query_handler(self, query, address):

        for q in query.questions:

            # Check if it is the initialization request
            if "NFXGS5A" in str(q.qname).upper():
                msgParts = str(q.qname).split(".")
                print(msgParts)
                
                filename = fromBase32(msgParts[2]).decode('utf-8') # Name of the file being exfiltrated
                #filename = filename
                print('message:' + filename)
		
                nb_chunks = fromBase32(msgParts[3]).decode('utf-8') # Total number of chunks of data expected to receive
                #nb_chunks = nb_chunks.decode('utf-8')
                print('nbChunks:' + nb_chunks)

                checksum = fromBase32(msgParts[4]).decode('utf-8') # Total number of chunks of data expected to receive
                #checksum = checksum.decode('utf-8')
                print('checksum:' + checksum)	

                # Reset all variables
                fileData = ''
                chunkIndex = 0	
                
                #print ("[+] Receiving file [{}] as a ZIP file in [{}] chunks".format(fileName,nbChunks))
                
                reply = dnslib.DNSRecord(dnslib.DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)	
                #reply.add_answer(dnslib.RR(query.q.qname, dnslib.QTYPE.TXT, rdata=dnslib.TXT("OK")))
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