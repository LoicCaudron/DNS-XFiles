# DNS-XFiles

Author: Loïc Caudron

DNS-XFiles exfiltrates a file by tunneling data through the DNS protocol. This tool was developed during a master thesis entitled "Classification of malicious behaviors based on DNS-over-HTTPS traffic analysis". It was mainly developed as a tool for testing data leakage.

DNS-XFiles, written in Python, consists of two parts:

- The **server side** (server.py), which represents the code executed by the attacker, acts as a custom DNS server and has the objective of collecting the data transmitted through the DNS protocol included in the DNS query for the specified domain and reconstructing the exfiltrated file.

- The **client side** (client.py), which represents the code executed on the victim's machine. Its purpose is to exfiltrate the desired files, process the data so that it can be transferred, and subdivide the data so that each piece can be encapsulated in a DNS query.


DNS-XFiles can operate both locally and over a network. In the latter case, you need to own a domain name and configure the DNS record (NS) of this domain to point to the server machine that will run the server side of DNS-XFiles.

### ⚠️ Disclaimer ⚠️
> 
> The DNS-XFiles repository and its software are intended for educational and research purposes only. 
    > either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
    > on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)
>    
> Use of DNS-XFiles for illegal activities or unauthorized access is strictly prohibited. The authors and contributors are not responsible for any misuse or damages caused by the use of this software.

## Features

- Variation in the size of DNS queries specified by the user during the same communication during file exfiltration
- Variation in the delay specified by the user between each DNS query sent by the client (to stay more stealthy when exfiltrating data).
- base32 encoding of exfiltrated data (avoids "_letter case randomization_", a technique used by some DNS resolvers to make protocol use more secure by modifying the case of letters)

## Python requirements

- Python 3.6 &rarr; 3.12

## Getting started
Clone the GitHub repository: 

```bash
git clone https://github.com/LoicCaudron/DNS-XFiles.git
```

Then, install requirements: 

```bash
pip install -r requirements.txt
```

## Usage

### Server

```bash
usage: server.py [-h] [-s SOCKET] [-d DOMAIN]

DNS-XFiles (LoicCaudron)

options:
  -h, --help            show this help message and exit
  -s SOCKET, --socket SOCKET
                        The upstream server for making DNS requests and the port (eg. '-s 0.0.0.0:53')
  -d DOMAIN, --domain DOMAIN
                        The domain to make requests for. (eg. '-d test.com')
```

### Client

```bash
usage: client.py [-h] [-s SOCKET] [-f FILE [FILE ...]] [-d DOMAIN]

options:
  -h, --help            show this help message and exit
  -s SOCKET, --socket SOCKET
                        The upstream server for making DNS requests and the port (eg. '-s 127.0.0.1:53')
  -f FILE [FILE ...], --file FILE [FILE ...]
                        File to exfiltrate (eg. '-f /etc/passwd /etc/group')
  -d DOMAIN, --domain DOMAIN
                        The domain to make requests for. (eg. '-d test.com')
```

#### Client JSON configuration

```json
{
  "minTimeSleep": 0.5,
  "maxTimeSleep": 1,
  "minSizeRequest": 75,
  "maxSizeRequest": 100
}
```

- minTimeSleep: minimum delay between each DNS query (in seconds)
- maxTimeSleep: maximum delay between each DNS query (in seconds)
- minSizeRequest: minimum size of the DNS queries (in bytes)
- maxSizeRequest: maximum size of the DNS queries (in bytes)



## How it works

To exfiltrate a file, the server part of DNS-XFiles must first be started and a domain name (e.g. exfil.com) set.

Once this has been done, the file exfiltration process can be launched by the client. The client first searches for the file in the path specified. If it exists and is not empty, the client reads the data and calculates the file checksum using the MD5 hash algorithm. The data is then encoded in base32 and not base64 to avoid the "letter case randomization" technique applied by some DNS resolvers to modify the case of letters and provide greater security against DNS spoofing and cache poisoning attacks. This data is then stored in a temporary file.

The client then initializes the connection with the server with an initialization request containing the information needed to exfiltrate the file. Once the server has responded to this initialization request, the client continues its execution, reading the data in the temporary file in chunks of random size. The size of the data extracted in a query depends on the maximum size of the query, taken at random from the minimum and maximum size of the DNS query specified by the user, and the size of the elements required for transmission present in the DNS query. Between each query, a random delay chosen from a user-specified interval is used.

In order to establish a system of connection reliability, the server responds to each request received from the client, and the client waits for this response before sending the rest of the data.

Once exfiltration is complete, the client sends a final request to indicate that all data has been sent. The server then reconstructs the data in the transmitted file, decodes it, calculates and verifies the MD5 checksum of the transmitted data and compares it with that present in the initialization request. If both checksums are equal, the server saves the file data.

![Communication flow](/docs/communication_flow.png)

## Credits

Credits go to several people I got inspired by or for some parts of the code:

- [https://github.com/PaulSec/DET](https://github.com/PaulSec/DET) from PaulSec
- [https://github.com/Arno0x/DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) from Arno0x0x.
- [https://github.com/Nicicalu/DNShell](https://github.com/Nicicalu/DNShell) from Nicicalu (Nicolas Caluori).
