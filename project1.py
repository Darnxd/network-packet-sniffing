import socket
import struct
import textwrap

def eth_addr(addr):
    return ':'.join('%02x' % b for b in addr)

def main():
    # Create a raw socket and bind it to the public interface
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
        print('\nEthernet Frame:')
        print(f'  Destination: {eth_addr(dest_mac)}')
        print(f'  Source: {eth_addr(src_mac)}')
        print(f'  Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8:
            # Unpack IP header
            ip_header = raw_data[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dest_addr = socket.inet_ntoa(iph[9])

            print('IPv4 Packet:')
            print(f'  Version: {version}')
            print(f'  Header Length: {ihl} words')
            print(f'  TTL: {ttl}')
            print(f'  Protocol: {protocol}')
            print(f'  Source Address: {src_addr}')
            print(f'  Destination Address: {dest_addr}')

            # TCP
            if protocol == 6:
                t = iph_length + 14
                tcp_header = raw_data[t:t+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                print('TCP Segment:')
                print(f'  Source Port: {src_port}')
                print(f'  Destination Port: {dest_port}')
                print(f'  Sequence Number: {sequence}')
                print(f'  Acknowledgement: {acknowledgement}')
                print(f'  Header Length: {tcph_length} words')

            # UDP
            elif protocol == 17:
                u = iph_length + 14
                udp_header = raw_data[u:u+8]
                udph = struct.unpack('!HHHH', udp_header)
                src_port = udph[0]
                dest_port = udph[1]
                length = udph[2]

                print('UDP Segment:')
                print(f'  Source Port: {src_port}')
                print(f'  Destination Port: {dest_port}')
                print(f'  Length: {length}')

if __name__ == '__main__':
    main()
