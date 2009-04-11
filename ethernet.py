import struct

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
        self.header_length = ((ord(data[12:13]) & 0xf0) >> 4) * 32 / 8
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
        self.data = data[self.header_length:ip.total_length - ip.header_len]

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
        tcp = TCPPacket(ip.data, ip)
        stream = find_stream(tcp, streams)
        if not stream:
            stream = TCPStream(tcp)
            streams.append(stream)
        else:
            stream.add_packet(tcp)
        p = f.next_packet()
    return streams

if __name__ == '__main__':
    print len(tcp_streams_from_file('C:\\test.pcap'))
