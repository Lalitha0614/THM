# Nmap 
[Link](https://tryhackme.com/room/furthernmap)

## Port Scanning : 
When a computer runs a network service, it opens a networking construct called port to recieve a connection. Connection made between an open port on our computer to servers port.

On a network enables domputer 65535 ports are available.
- 0-1023 - well-known ports (standard ports)
- 1024-49151 - registered ports - assigned to specific applications
- 49151-65535 - dynamic ports


<img src="https://github.com/user-attachments/assets/dec2908d-5313-4829-b3c7-f23c1c343dc6" width="500" height="400">

## Port Numbers :
1. `80` - HTTP
2. `443` - HTTPS
3. `139` - Windows NETBIOS
4. `445` - SMB
5. `22`  - SSH



Attackes first does port scan to know the open ports of the target . There are many ways to do it, one of them is Nmap

Aport can be closed, open or filtered(usually by firewall).

Once we know the open ports, we can look at services running on that port by nmap or other tools 

## Nmap 

```bash
namp <switches>
```
switches - command arguments which tell a program to do different things 
try nmap -h or man nmap for more information 


Some switches <br>
`-sS` - Syn Scan <br>
`-sU` - UDP Scan<br>
`-O`  - OS Detection <br>
`-sV` - Version detection<br>
`-V`  - Increase verbosity<br>
`-vv` - higher verbosity level<br>
`-oA` - Output in three major formats<br>
`-oN` - Output in normal format<br>
`-oG` - Output in grepable format<br>
`-A`  - Enable OS detection, version detection, script scanning, and traceroute<br>
`-T0-5` Timing levels<br>
`-p .`- Scan only specified ports <br>
`-p-` - Scan all ports<br>
`--script` - acticvating a script from nmap scripting library <br>

## Basic nmap scan types
`-sT` - TCP Connect Scans <br>
`-ss` - SYN Half Open Scans <br>
`-sU` - UDP Scans <br>

TCP Null Scans `(-sN)` <br>
TCP FIN Scans `(-sF)` <br>
TCP Xmas Scans `(-sX)` <br>

---

## TCP CONNECT SCANS `-sT`
Recap : TCP - 3 way handshake (syn, syn/ack, ack)
TCP Connect scan -sT works by performing the three-way handshake with each target port in turn. In other words, Nmap tries to connect to each specified TCP port, and determines whether the service is open by the response it receives.
Stateful

If the port is  **open**, syn/ack response is recieved, if it is **closed**, it will recieve RST flag (Reset), with this response nmap will learn that the port is closed.
If no response is recieved it means it is blocked by firewall and packet is dropped, then port is displayed as **Filtered**

We can easily configuer a firewall to respond with RST TCP packet, for example
```bash
iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset
```
---

## SYN SCANS `-sS` 
These are used to scan the TCP Port range of target
Half-open scans or Stealth scans

Where TCP scans perform a full three-way handshake with the target, SYN scans sends back a RST TCP packet after receiving a SYN/ACK from the server (this prevents the server from repeatedly trying to make the request)

---

## UDP SCANS `-sU`
Stateless, connections rely on sending packets to a target port and essentially hoping that they make it
When there is no ressponse, the port can be open or filtered. If it gets respons(rare), open.When port is **closed**, responds with ICMP packet containing message that port is unreachabe
As it is very slow, we scan only some ports (--top-ports <number>)like
```bash
nmap -sU --top-ports 20 <target>
```
---

## NULL, FIN and Xmas Port scans 
more stealthier than syn scan 
All threee are mainly used for firewall evasion 

**NULL SCAN `-sN`**
TCP request is sent with no flags set at all, reply comes with RST,ACK if port is closed

**FIN scans `(-sF)`**
almost same as null, 
instead of sending a completely empty packet, a request is sent with the FIN flag (usually used to gracefully close an active connection). Once again, Nmap expects a RST,ACK if the port is closed.

**Xmas scans `(-sX)` **
send a malformed TCP packet and expects a RST,ACK response for closed ports.<br>
It's referred to as an xmas scan as the flags that it sets (PSH, URG and FIN) give it the appearance of a blinking christmas tree when viewed as a packet capture in Wireshark.

For all these three scans if the port is open then there is no response to the malformed packet

- RFC 793 mandates that network hosts respond to malformed packets with a RST TCP packet for closed ports,  and don't respond at all for open ports. But this is not always the case.
- Microsoft Windows (and a lot of Cisco network devices) are known to respond with a RST to any malformed TCP packet -- regardless of whether the port is actually open or not.

FIREWALLS - drop incoming tcp packets to block ports having SYN flags.
We can bypass this by firewall by not sending syn flag

---

To get a map of the network structure or to see which IP addressses have active hosts
**ping sweep `(-sn)`** <br>
primarily relys on ICMP echo packets (or ARP requests on a local network and also sends  TCP SYN packet to port 443 of the target, as well as a TCP ACK (or TCP SYN if not run as root) packet to port 80 of the target. 

Nmap sends an ICMP packet to each possible IP address for the specified network. When it receives a response, it marks the IP address that responded as being alive
```bash
nmap -sn 192.168.0.1-254 or nmap -sn 192.168.0.0/24
```

---

## Nmap Scripting Engine (NSE)

NSE Scripts are written in the Lua programming language.Scanning for vulnerabilitties, automating exploits, reconnaisance

Categories: [link](https://nmap.org/book/nse-usage.html)

safe:- Won't affect the target
intrusive:- Not safe: likely to affect the target
vuln:- Scan for vulnerabilities
exploit:- Attempt to exploit a vulnerability
auth:- Attempt to bypass authentication for running services (e.g. Log into an FTP server anonymously)
brute:- Attempt to bruteforce credentials for running services
discovery:- Attempt to query running services for further information about the network (e.g. query an SNMP server).

To run a script `--script=<script-name>`
multiple scripts `--script=smb-enum-users,smb-enum-shares`
script args : `--script-args`
EG: http-put script (used to upload files using the PUT method). This takes two arguments: the URL to upload the file to, and the file's location on disk.
```bash
nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php'
```
help: 
`nmap --script-help <script-name>`

Where the find the scripts in nmap 
1. [Link](https://nmap.org/nsedoc/) - contains list of all official scripts
2. /usr/share/nmap/scripts - all the scripts are stored here

2 ways to find installed scripts :
1. `/usr/share/nmap/scripts/script.db` this isn't actually a database so much as a formatted text file containing filenames and categories for each available script.

<img src="https://github.com/user-attachments/assets/1cc5bc5b-4f50-4be5-b895-2d72527cca7e" width="500" height="400">

we can also grep to find scripts `grep "ftp" /usr/share/nmap/scripts/script.db`
2. using ls command 
`ls -l /usr/share/nmap/scripts/*ftp*`

if some scripts are missing, `sudo apt update && sudo apt install nmap`
Manually downloading script in nmap 
`sudo wget -O /usr/share/nmap/scripts/<script-name>.nse`
`https://svn.nmap.org/nmap/scripts/<script-name>.nse`
`nmap --script-updatedb` -  this updates this script to script.db

## Firewall evasion 

bypassing firewall for scans -  common firewall configurations - stealth scans, along with NULL, FIN and Xmas scans

windows will in default block all icmp packets 









