import struct
import sys
import array

from pcap import PcapFile

class EthernetPacket():
    def __init__(self, data):
        self.destination = self._mac_bytes_to_str(data[0:6])
        self.source = self._mac_bytes_to_str(data[6:12])
        self.type = data[12:14]
        self.data = data[14:]

    def _mac_bytes_to_str(self, bytes):
        unpacked = struct.unpack('BBBBBB', bytes)
        result = ''
        for b in unpacked:
            result += '%02x:' % b
        return result[:-1]

class IPPacket():
    def __init__(self, data, ethernet):
        self.ethernet = ethernet
        self.version = (ord(data[0:1]) & 0xf0) >> 4
        self.header_len = (ord(data[0:1]) & 0x0f) * 32 / 8
        self.tos = ord(data[1:2])
        self.total_length = struct.unpack('!H', data[2:4])[0]
        self.identification = data[4:6]
        self.flags = (ord(data[6:7]) & 0xe0)
        self.reserved = self.flags & 0x20 == 0x20
        self.dont_fragment = self.flags & 0x40 == 0x40
        self.more_fragments = self.flags & 0x80 == 0x80
        self.fragment_offset = (struct.unpack('!H', data[6:8])[0] & 0xff1f)
        self.ttl = ord(data[8:9])
        self.protocol = ord(data[9:10])
        self.checksum = data[10:12]
        self.source = self._ip_bytes_to_str(data[12:16])
        self.destination = self._ip_bytes_to_str(data[16:20])
        self.data = data[20:]

    def _ip_bytes_to_str(self, bytes):
        unpacked = struct.unpack('BBBB', bytes)
        return '%d.%d.%d.%d' % unpacked

class TCPPacket():
    def __init__(self, data, ip):
        self.ip = ip
        self.source_port = struct.unpack('!H', data[0:2])[0]
        self.destination_port = struct.unpack('!H', data[2:4])[0]
        self.seq_no = struct.unpack('!I', data[4:8])[0]
        self.ack_no = struct.unpack('!I', data[8:12])[0]
        self.header_length = (((ord(data[12:13]) & 0xf0) >> 4) * 32) // 8
        self.cwr = ord(data[13:14]) & 0x80 == 0x80
        self.ecn = ord(data[13:14]) & 0x40 == 0x40
        self.urgent = ord(data[13:14]) & 0x20 == 0x20
        self.ack = ord(data[13:14]) & 0x10 == 0x10
        self.push = ord(data[13:14]) & 0x08 == 0x08
        self.reset = ord(data[13:14]) & 0x04 == 0x04
        self.syn = ord(data[13:14]) & 0x02 == 0x02
        self.fin = ord(data[13:14]) & 0x01 == 0x01
        self.window = struct.unpack('H', data[14:16])[0]
        self.checksum = data[16:18]        

        rest = int(ip.total_length - ip.header_len)
        self.data = data[self.header_length:rest]




if struct.pack("H", 1) == b"\x00\x01":  # big endian
    checksum_endian_transform = lambda chk: chk
else:
    checksum_endian_transform = lambda chk: ((chk >> 8) & 0xff) | chk << 8

def checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return checksum_endian_transform(s) & 0xffff


class UDPPacket():
    def __init__(self, data, ip):
        self.ip = ip
        self.source_port = struct.unpack('!H', data[0:2])[0]
        self.destination_port = struct.unpack('!H', data[2:4])[0]
        self.length = struct.unpack('!H', data[4:6])[0]
        self.checksum = data[6:8]
        self.data = data[8:]


    def _checksum_valid(self):
        
        pseudo = bytearray(len(self.ip.data) + 12)
        pseudo[0:4]  = self.ip.ethernet.data[12:16] # source
        pseudo[4:8]  = self.ip.ethernet.data[16:20] # dest
        pseudo[8]    = 0x0  # 0
        pseudo[9]    = 0x11 # 17
        pseudo[10:12] = struct.pack('!H', self.length)   # udp total length 
       
       # udp header
        pseudo[12:14] = struct.pack('!H', self.source_port)
        pseudo[14:16] = struct.pack('!H', self.destination_port)
        pseudo[16:18] = struct.pack('!H', self.length)
        pseudo[18:20] = struct.pack('!H', 0) # checksum, vai 0
        pseudo[20:]   = self.data

        return ((checksum(pseudo)) == struct.unpack('!H', self.checksum)[0])



class ICMPPacket():
    def __init__(self, data, ip):
        self.ip = ip

        self.type = data[0]
        self.code = data[1]

        self.checksum = data[2:3]

        self.data = data[4:7]


# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#header_rest
icmptypes = {0: "Echo reply",
             3: "Destination network unreachable",
             4: "Source quench (congestion control)",
             5: "Redirect",
             8: "Echo request",
             9: "Router Advertisement",
             10: "Router solicitation",
             11: "Time Exceeded",
             12: "Parameter problem",
             13: "Timestamp",
             14: "Timestamp Reply",
             15: "Information Request",
             16: "Information Reply",
             17: "Address Mask Request",
             18: "Address Mask Reply",
             30: "Traceroute"}   

icmpcodes = {0: "",
             3: {0: "Destination network unreachable",
                    1: "	Destination host unreachable",
                    2: "Destination protocol unreachable",
                    3: "Destination port unreachable",
                    4: "Fragmentation required, and DF flag set",
                    5: "Source route failed",
                    6: "Destination network unknown",
                    7: "Destination host unknown",
                    8: "Source host isolated",
                    9: "Network administratively prohibited",
                    10: "Host administratively prohibited",
                    11: "Network unreachable for ToS",
                    12: "Host unreachable for ToS",
                    13: "Communication administratively prohibited",
                    14: "Host Precedence Violation",
                    15: "Precedence cutoff in effect", },
             5: {0: "Redirect Datagram for the Network",
                 1: "Redirect Datagram for the Host",
                 2: "Redirect Datagram for the ToS & network",
                 3: "Redirect Datagram for the ToS & host", },
             11: {0: "TTL expired in transit",
                  1: "Fragment reassembly time exceeded", },
             12: {0: "Pointer indicates the error",
                  1: "Missing a required option", 
                  2: "Bad length"}}   
        

class TCPStream():
    def __init__(self, initial_packet):
        self.sender = initial_packet.ip.source
        self.receiver = initial_packet.ip.destination
        self.sport = initial_packet.source_port
        self.dport = initial_packet.destination_port
        self.send_packets = [initial_packet]
        self.recv_packets = []

    def right_stream(self, packet):
        return (((packet.source_port == self.sport 
                  and packet.destination_port == self.dport)
                 or (packet.source_port == self.dport 
                     and packet.destination_port == self.sport))
                and ((packet.ip.source == self.sender 
                      and packet.ip.destination == self.receiver)
                     or (packet.ip.source == self.receiver 
                         and packet.ip.destination == self.sender)))
    
    def add_packet(self, packet):
        if packet.ip.source == self.sender:
            self.send_packets.append(packet)
        else:
            self.recv_packets.append(packet)

    def sent_data(self):
        a = self.send_packets 
        a.sort(lambda a, b: a.seq_no > b.seq_no)
        return ''.join([p.data for p in a])

    def recv_data(self):
        a = self.recv_packets
        a.sort(lambda a, b: a.seq_no > b.seq_no)
        return ''.join([p.data for p in a])

def find_stream(packet, streams):
    for stream in streams:
        if stream.right_stream(packet):
            return stream
    return None

def tcp_streams_from_file(path):
    streams = []
    f = PcapFile(path)
    p = f.next_packet()

    while p != None:

        e = EthernetPacket(p.data)
        ip = IPPacket(e.data, e)

        if ip.protocol != 6:  #tcp
            p = f.next_packet()
            continue

        tcp = TCPPacket(ip.data, ip)
        stream = find_stream(tcp, streams)
        if not stream:
            stream = TCPStream(tcp)
            streams.append(stream)
        else:
            stream.add_packet(tcp)

        p = f.next_packet()
    return streams

def udp_packets_from_file(path):
    packets = []

    f = PcapFile(path)
    p = f.next_packet()

    while p != None:

        e = EthernetPacket(p.data)
        ip = IPPacket(e.data, e)

        if ip.protocol != 17:  # udp
            p = f.next_packet()
            continue


        udp = UDPPacket(ip.data, ip)

        print(udp.source_port, '>', udp.destination_port, 'len=', udp.length)
        
        if udp._checksum_valid():
            print('checksum ok')
        else:
            print('checksum bad')

        packets.append(ip)
        p = f.next_packet()

    return packets


def icmp_packets_from_file(path):
    packets = []

    f = PcapFile(path)
    p = f.next_packet()

    while p != None:

        e = EthernetPacket(p.data)
        ip = IPPacket(e.data, e)

        if ip.protocol != 1:  # icmp
            p = f.next_packet()
            continue


        icmp = ICMPPacket(ip.data, ip)

        if icmp.code != 0:
            codestr = icmpcodes[icmp.type][icmp.code]
        else:
            codestr = ''

        print(ip.source, '>', ip.destination)
        print('type : ', icmp.type, icmptypes[icmp.type], ' | code : ', icmp.code, codestr)
        print('')

        packets.append(ip)


        p = f.next_packet()

    return packets

def packets_from_file(path):
    packets = []

    f = PcapFile(path)
    p = f.next_packet()

    while p != None:

        e = EthernetPacket(p.data)
        ip = IPPacket(e.data, e)

        if ip.protocol == 1:  # icmp    
            proto = 'ICMP'
            icmp = ICMPPacket(ip.data, ip)

            if icmp.code != 0:
                codestr = icmpcodes[icmp.type][icmp.code]
            else:
                codestr = ''

            info = 'type : ' + str(icmp.type) + ' - ' + icmptypes[icmp.type] + ' | code : ' + str(icmp.code) + ' ' + codestr

        if ip.protocol == 6: #tcp
            proto = 'TCP'
            tcp = TCPPacket(ip.data, ip)

            info = str(tcp.source_port).ljust(7) + ' > ' + str(tcp.destination_port).ljust(7) + ' | ' + ' Seq = ' + str(tcp.seq_no) + ' Ack = ' + str(tcp.ack_no) + 'Win = ' + str(tcp.window)

        if ip.protocol == 17: #udp
            proto = 'UDP'
            udp = UDPPacket(ip.data, ip)

            info = str(udp.source_port).ljust(7) + ' > ' + str(udp.destination_port).ljust(7) + ' Len = ' + str(udp.length).ljust(6)
            
            if not udp._checksum_valid():
                info = info + ' | invalid checksum'



        print(ip.source.ljust(16), ' | ', ip.destination.ljust(16), ' | ',  proto.ljust(4), ' |  ', info)
        
        packets.append(ip)

        p = f.next_packet()

    return packets

if __name__ == '__main__':
    print(len(packets_from_file("test.pcap")))

