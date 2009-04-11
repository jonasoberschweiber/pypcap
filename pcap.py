import struct

PCAP_GLOBAL_HEADER_FORMAT = 'IHHiIII'
PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PACKET_HEADER_FORMAT = 'IIII'
PCAP_PACKET_HEADER_LEN = 16

class PcapFile():
    def __init__(self, filename):
        self.f = open(filename, 'rb')
        header_data = self.f.read(PCAP_GLOBAL_HEADER_LEN)
        self.global_header = PcapGlobalHeader(header_data)

    def next_packet(self):
        header_data = self.f.read(PCAP_PACKET_HEADER_LEN)
        if not len(header_data):
            return None
        packet = PcapPacket(header_data)
        data = self.f.read(packet.incl_len)
        packet.data = data
        return packet

class PcapGlobalHeader():
    def __init__(self, data):
        unpacked = struct.unpack(PCAP_GLOBAL_HEADER_FORMAT, data)
        self.magic_number = unpacked[0]
        self.swapped = self.magic_number != 0xa1b2c3d4
        self.version_major = unpacked[1]
        self.version_minor = unpacked[2]
        self.thiszone = unpacked[3]
        self.sigfigs = unpacked[4]
        self.snaplen = unpacked[5]
        self.network = unpacked[6]

class PcapPacket():
    def __init__(self, header_data):
        unpacked = struct.unpack(PCAP_PACKET_HEADER_FORMAT, header_data)
        self.ts_sec = unpacked[0]
        self.ts_usec = unpacked[1]
        self.incl_len = unpacked[2]
        self.orig_len = unpacked[3]


