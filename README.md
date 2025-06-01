# network-packet-sniffing
Simple Python packet sniffer using raw sockets on Linux. Captures and prints raw network packets at Layer 2, enabling low-level traffic monitoring. Educational tool for learning raw sockets, packet structures, and network traffic capture. Requires root privileges. For authorized use only.

# Python Packet Sniffer

This is a basic packet sniffer written in Python for Linux systems. It uses raw sockets to capture and print raw network packets directly from the network interface at the data link layer (Layer 2).

## Features

- Captures all network packets regardless of protocol  
- Prints raw packet data in real time  
- Uses Python's built-in `socket` library  
- Educational tool for learning low-level network programming

## Requirements

- Python 3.x  
- Linux (tested on Kali Linux)  
- Root privileges (required to open raw sockets)

## Installation

Clone the repository:

```bash
git clone https://github.com/Darnxd/network-packet-sniffing.git

cd network-packet-sniffing

