from socket import socket, AF_INET , SOCK_STREAM , AF_PACKET, IPPROTO_IP, ntohs, getfqdn, gethostbyname, gethostname, setdefaulttimeout, IPPROTO_TCP, inet_aton, SOCK_RAW, IP_HDRINCL
from struct import pack, unpack
from random import randint
from time import time
from socket import SOCK_DGRAM, getservbyport


class IPv4_packet:
    def __init__(self, source_address, destination_address):
        self.header = self.pack_to_bytes(source_address, destination_address)

    # def __init__(self, data):
    #     self.datagram = self.parse_ipv4_datagram(data) # 0: version, 1: IHL, 2: DSCP, 3: ECN, 4: total_length, 5: identification, 6: DF, 7: MF, 8: offset, 9: TTL, 10: Protocol,  11: checksum, 12: source_IP_address, 13: destination_IP_address, 14: datagram_payload
    #     self.raw_data = data
    #
    # def parse_ipv4_datagram(self, data):
    #     version_and_ihl, DSCP_and_ECN, total_length, identification, flags_and_fragment_offset, TTL, Protocol, checksum, source_IP_address, destination_IP_address = unpack('! B B H H H B B H 4s 4s', data[:20])
    #     version = version_and_ihl >> 4
    #     IHL = (version_and_ihl & 15)  #Internet Header Length is the low_order 4 bits and determines the number of 32-bit fields
    #     DSCP = DSCP_and_ECN >> 2
    #     ECN = (DSCP_and_ECN & 0x03)
    #     DF = (flags_and_fragment_offset & 0x4000) << 14
    #     MF = (flags_and_fragment_offset & 0x2000) << 13
    #     offset = (flags_and_fragment_offset & 0x1FFF) * 8
    #     return version, IHL, DSCP, ECN, total_length, identification, DF, MF, offset, TTL, Protocol, checksum, source_IP_address, destination_IP_address, data[IHL * 4:]
    #
    # def print(self):
    #     print("IPv4 Datagram:")
    #     print(f'\t-Version: {self.datagram[0]} -Header Length: {self.datagram[1]} -DSCP: {self.datagram[2]} -ECN: {self.datagram[3]} -Total Length: {self.datagram[4]} ')
    #     print(f'\t-Identification: {self.datagram[5]} -DF: {self.datagram[6]} -MF: {self.datagram[7]} -Offset: {self.datagram[8]} -TTL: {self.datagram[9]} -Protocol: {self.datagram[10]}')
    #     print(f'\t-Checksum: {self.datagram[11]} -Source Address: {self.format_IP_address(self.datagram[12])} -Destination Address: {self.format_IP_address(self.datagram[13])}')
    #
    # def format_IP_address(self, IP_address):
    #     formatted_address = '.'.join(map(str ,IP_address))
    #     return formatted_address
    #
    # def protocol_is_UDP(self):
    #     return self.datagram[10] == 17 # 0x11 IP protocol number for UDP
    #
    # def protocol_is_TCP(self):
    #     return self.datagram[10] == 6 # 0x06 IP protocol number for TCP
    #
    # def protocol_is_ICMP(self):
    #     return self.datagram[10] == 1 # 0x01 IP protocol number for ICMP
    #

    def pack_to_bytes(self, source_address, destination_address):
        version = 4
        IHL = 5
        version_and_ihl = (version << 4) + IHL
        DSCP_and_ECN = 0
        total_length = 20 + 20  # IPV4 + TCP : 20 bytes each
        identification = randint(1, 2 ** 16)
        flags_and_fragment_offset = 0
        TTL = 255
        Protocol = IPPROTO_TCP
        checksum = 10  # WHAT?
        _source_address = inet_aton(source_address)
        _destination_address = inet_aton(destination_address)
        return pack('! B B H H H B B H 4s 4s', version_and_ihl, DSCP_and_ECN, total_length, identification,
                              flags_and_fragment_offset, TTL, Protocol, checksum, _source_address, _destination_address)

class TCP_packet:
    def __init__(self, source_port, destination_port, source_address, destination_address, scan_model):
        self.packet = self.pack_to_bytes(source_port, destination_port, source_address, destination_address, scan_model)

    def pack_to_bytes(self, source_port, destination_port, source_address, destination_address, scan_model):
        ipv4_header = IPv4_packet(source_address, destination_address).header
        sequence_number = 0
        acknowledgement_number = 0
        offset = 5
        reserved = 0
        NS = 0
        offset_and_reserved_and_NS_flag = (offset << 4) + reserved + NS
        CWR = ECE = URG  = PSH = RST = 0
        if scan_model == 'AS' or scan_model == 'WS': #Ack scan or window scan
            ACK = 1
            SYN = FIN = 0

        elif scan_model == 'SS': #Syn scan
            ACK = FIN = 0
            SYN = 1

        elif scan_model == 'FS': #Fin scan
            ACK = SYN = 0
            FIN = 1

        flags = (ACK << 4) + (SYN << 1) + FIN
        window_size = 1024
        invalid_checksum = 0
        urgent_pointer = 0
        _source_address = inet_aton(source_address)
        _destination_address = inet_aton(destination_address)
        tcp_header = pack('! H H L L B B H H H', source_port, destination_port, sequence_number, acknowledgement_number, offset_and_reserved_and_NS_flag, flags, window_size, invalid_checksum, urgent_pointer)
        temp = pack('! 4s 4s B B H', _source_address, _destination_address, 0, IPPROTO_TCP, len(tcp_header))
        temp += tcp_header
        checksum = self.checksum(temp)
        tcp_header = pack('! H H L L B B H H H', source_port, destination_port, sequence_number,
                          acknowledgement_number, offset_and_reserved_and_NS_flag, flags, window_size, checksum,
                          urgent_pointer)
        return ipv4_header + tcp_header

    def checksum(self, data):
        sum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            sum += word
        carry = sum >> 16
        new_sum = carry + (sum & 0xFFFF)
        _checksum = (~new_sum) & 0xFFFF
        return _checksum

class IPv4:
    def __init__(self, data):
        self.datagram = self.parse_ipv4_datagram(data) # 0: version, 1: IHL, 2: DSCP, 3: ECN, 4: total_length, 5: identification, 6: DF, 7: MF, 8: offset, 9: TTL, 10: Protocol,  11: checksum, 12: source_IP_address, 13: destination_IP_address, 14: datagram_payload
        self.raw_data = data

    def parse_ipv4_datagram(self, data):
        version_and_ihl, DSCP_and_ECN, total_length, identification, flags_and_fragment_offset, TTL, Protocol, checksum, source_IP_address, destination_IP_address = unpack('! B B H H H B B H 4s 4s', data[:20])
        version = version_and_ihl >> 4
        IHL = (version_and_ihl & 15)  #Internet Header Length is the low_order 4 bits and determines the number of 32-bit fields
        DSCP = DSCP_and_ECN >> 2
        ECN = (DSCP_and_ECN & 0x03)
        DF = (flags_and_fragment_offset & 0x4000) << 14
        MF = (flags_and_fragment_offset & 0x2000) << 13
        offset = (flags_and_fragment_offset & 0x1FFF) * 8
        return version, IHL, DSCP, ECN, total_length, identification, DF, MF, offset, TTL, Protocol, checksum, source_IP_address, destination_IP_address, data[IHL * 4:]

    def print(self):
        print("IPv4 Datagram:")
        print(f'\t-Version: {self.datagram[0]} -Header Length: {self.datagram[1]} -DSCP: {self.datagram[2]} -ECN: {self.datagram[3]} -Total Length: {self.datagram[4]} ')
        print(f'\t-Identification: {self.datagram[5]} -DF: {self.datagram[6]} -MF: {self.datagram[7]} -Offset: {self.datagram[8]} -TTL: {self.datagram[9]} -Protocol: {self.datagram[10]}')
        print(f'\t-Checksum: {self.datagram[11]} -Source Address: {self.format_IP_address(self.datagram[12])} -Destination Address: {self.format_IP_address(self.datagram[13])}')

    def format_IP_address(self, IP_address):
        formatted_address = '.'.join(map(str ,IP_address))
        return formatted_address

    def protocol_is_UDP(self):
        return self.datagram[10] == 17 # 0x11 IP protocol number for UDP

    def protocol_is_TCP(self):
        return self.datagram[10] == 6 # 0x06 IP protocol number for TCP

    def protocol_is_ICMP(self):
        return self.datagram[10] == 1 # 0x01 IP protocol number for ICMP

class TCP:
    def __init__(self, data):
        self.segment = self.parse_tcp_segment(data) # 0: source_port_number, 1: destination_port_number, 2: sequence_number, 3: acknowledgement_number, 4: data_offset, 5: NS, 6: CWR, 7: ECE, 8: URG, 9: ACK, 10: PSH, 11: RST, 12: SYN, 13: FIN, 14: window_size, 15: checksum, 16: urgent_pointer, 17: payload
        self.raw_data =data

    def parse_tcp_segment(self, data):
        source_port_number, destination_port_number, sequence_number, acknowledgement_number, offset_and_flags, window_size, checksum, urgent_pointer = unpack('! H H L L H H H H', data[:20])
        data_offset = (offset_and_flags >> 12)
        NS = (offset_and_flags & 0x100) >> 8
        CWR = (offset_and_flags & 0x80) >> 7
        ECE = (offset_and_flags & 0x40) >> 6
        URG = (offset_and_flags & 0x20) >> 5
        ACK = (offset_and_flags & 0x10) >> 4
        PSH = (offset_and_flags & 0x8) >> 3
        RST = (offset_and_flags & 0x4) >> 2
        SYN = (offset_and_flags & 0x2) >> 1
        FIN = (offset_and_flags & 0x1)
        payload = data[data_offset * 4:] if len(data) > data_offset else None
        return source_port_number, destination_port_number, sequence_number, acknowledgement_number, data_offset, NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN, window_size, checksum, urgent_pointer, payload

    def print(self):
        print('TCP Segment:')
        print(f'\t-Source Port: {self.segment[0]} -Destination Port: {self.segment[1]} -Sequence Number: {self.segment[2]} -Acknowledge Number; {self.segment[3]}')
        print(f'\t-Data Offset: {self.segment[4]} -NS: {self.segment[5]} -CWR: {self.segment[6]} -ECE: {self.segment[7]} -URG: {self.segment[8]} -ACK: {self.segment[9]} -PSH: {self.segment[10]} -RST: {self.segment[11]} -SYN: {self.segment[12]} -FIN: {self.segment[13]}')
        print(f'\t-Window Size: {self.segment[14]} -Checksum: {self.segment[15]} -Urgent Pointer: {self.segment[16]}')

    def is_DNS(self):
        return self.segment[0] == 53 or self.segment[1] == 53 #port number for DNS protocol

    def is_HTTP(self):
        return self.segment[0] == 80 or self.segment[1] == 80  # port number for HTTP protocol

class scan:
    def __init__(self, parameters):
        self.host_name = parameters[0][parameters[0].find(":") + 1 :]
        self.port_range = [int(num) for num in parameters[1][parameters[1].find(":") + 1 :].split('-')]
        self.scan_model = parameters[2][parameters[2].find(":") + 1 :]
        self.delay = int(parameters[3][parameters[3].find(":") + 1 :])

    #MODIFY
    def local_ip(self):
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        return s.getsockname()[0]

    #MODIFY
    def local_port(self):
        s = socket(AF_INET, SOCK_DGRAM)
        s.bind(('', 0))
        return s.getsockname()[1]

    def connect_scan(self):
        left_end = self.port_range[0]
        right_end = self.port_range[1] + 1
        host_address = gethostbyname(self.host_name)
        for port in range(left_end, right_end):
            scanning_socket = socket(AF_INET, SOCK_STREAM)
            setdefaulttimeout(self.delay)
            status = scanning_socket.connect_ex((host_address, port))
            if status == 0:
                print(f'port {port} running {getservbyport(port)} service is open')
            scanning_socket.close()

    def ack_scan(self):
        scanning_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
        scanning_socket.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        destination_address = gethostbyname(self.host_name)
        host_address = gethostbyname(getfqdn())
        tcp_packet = TCP_packet(self.local_port(), 80, self.local_ip(), destination_address, scan_model='AS').packet
        scanning_socket.sendto(tcp_packet, (destination_address, 0))
        self.wait_ack_scan(host_address, destination_address)

    def wait_ack_scan(self, host_address, destination_address):
            scanning_socket = socket(AF_PACKET, SOCK_RAW, ntohs(3))
            start_time = time()
            while time() - start_time < self.delay + 1:
                raw_data, address = scanning_socket.recvfrom(65535)
                ethernet_payload = raw_data[14:]
                IP_datagram = IPv4(ethernet_payload)
                if IP_datagram.format_IP_address(IP_datagram.datagram[12]) == destination_address :
                    if IP_datagram.protocol_is_TCP():
                        TCP_segment = TCP(IP_datagram.datagram[-1]).segment
                        if TCP_segment[11]:
                            print('Host is unfiltered')
                            scanning_socket.close()
                            return
                        else:
                            print('Host is filtered')
                            scanning_socket.close()
                            return

            print('Host is filtered')
            scanning_socket.close()
            return

    def syn_scan(self):
        scanning_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
        scanning_socket.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        destination_address = gethostbyname(self.host_name)
        host_address = gethostbyname(getfqdn())
        left_end = self.port_range[0]
        right_end = self.port_range[1] + 1
        for port in range(left_end, right_end):
            tcp_packet = TCP_packet(self.local_port(), port, self.local_ip(), destination_address, scan_model='SS').packet
            scanning_socket.sendto(tcp_packet, (destination_address, 0))
            self.wait_syn_scan(host_address, destination_address)

    def wait_syn_scan(self, host_address, destination_address):
            scanning_socket = socket(AF_PACKET, SOCK_RAW, ntohs(3))
            start_time = time()
            while time() - start_time < self.delay + 1:
                raw_data, address = scanning_socket.recvfrom(65535)
                ethernet_payload = raw_data[14:]
                IP_datagram = IPv4(ethernet_payload)
                if IP_datagram.format_IP_address(IP_datagram.datagram[12]) == destination_address:
                    if IP_datagram.protocol_is_TCP():
                        TCP_segment = TCP(IP_datagram.datagram[-1]).segment
                        if TCP_segment[9] and TCP_segment[12]:
                            #print(f'port {TCP_segment[0]} is open')
                            print(f'port {TCP_segment[0]} running {getservbyport(TCP_segment[0])} service is open')

    def fin_scan(self):
        scanning_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
        scanning_socket.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        destination_address = gethostbyname(self.host_name)
        host_address = gethostbyname(getfqdn())
        left_end = self.port_range[0]
        right_end = self.port_range[1] + 1
        for port in range(left_end, right_end):
            tcp_packet = TCP_packet(self.local_port(), port, self.local_ip(), destination_address, scan_model='FS').packet
            scanning_socket.sendto(tcp_packet, (destination_address, 0))
            self.wait_fin_scan(host_address, destination_address)

    def wait_fin_scan(self, host_address, destination_address):
            scanning_socket = socket(AF_PACKET, SOCK_RAW, ntohs(3))
            start_time = time()
            port = int()
            while time() - start_time < self.delay + 1:
                raw_data, address = scanning_socket.recvfrom(65535)
                ethernet_payload = raw_data[14:]
                IP_datagram = IPv4(ethernet_payload)
                if IP_datagram.format_IP_address(IP_datagram.datagram[12]) == destination_address:
                    if IP_datagram.protocol_is_TCP():
                        TCP_segment = TCP(IP_datagram.datagram[-1]).segment
                        port = TCP_segment[0]
                        if TCP_segment[11]:
                            pass
            if port:
                #print(f'port {port} is open')
                print(f'port {port} running {getservbyport(port)} service is open')

    def window_scan(self):
        scanning_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
        scanning_socket.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        destination_address = gethostbyname(self.host_name)
        host_address = gethostbyname(getfqdn())
        tcp_packet = TCP_packet(self.local_port(), 80, self.local_ip(), destination_address, scan_model='WS').packet
        scanning_socket.sendto(tcp_packet, (destination_address, 0))
        self.wait_window_scan(host_address, destination_address)

    def wait_window_scan(self, host_address, destination_address):
        while True:
            scanning_socket = socket(AF_PACKET, SOCK_RAW, ntohs(3))
            start_time = time()
            while time() - start_time < self.delay + 1:
                raw_data, address = scanning_socket.recvfrom(65535)
                ethernet_payload = raw_data[14:]
                IP_datagram = IPv4(ethernet_payload)
                if IP_datagram.format_IP_address(IP_datagram.datagram[12]) == destination_address:
                    if IP_datagram.protocol_is_TCP():
                        TCP_segment = TCP(IP_datagram.datagram[-1]).segment
                        if TCP_segment[11]:
                            print('Host is unfiltered')
                            scanning_socket.close()
                            return
                        else:
                            print('Host is filtered')
                            scanning_socket.close()
                            return

            print('Host is filtered')
            scanning_socket.close()
            return

def main():
    user_input = input('format: ///h:url p:x-y s:CS d:t///  for example: h:example.com p:80-1024 s:CS d:100\n scans for ports between 80 and 1024 on example.com with a delay of 100 second using a connection scan model:\n-CS: Sonnect scan -AS: Ack scan -SS: Syn scan -FS: Fin scan -WS: Window scan\n‬‬')
    parameters = user_input.split(' ')
    scanner = scan(parameters)
    if scanner.scan_model == 'CS':
        scanner.connect_scan()
    elif scanner.scan_model == 'AS':
        scanner.ack_scan()
    elif scanner.scan_model == 'SS':
        scanner.syn_scan()
    elif scanner.scan_model == 'FS':
        scanner.fin_scan()
    elif scanner.scan_model == 'WS':
        scanner.window_scan()

main()
