from checksum_f import checksum_f
from struct import *


class Packet:
    def __init__(self, packet_type):
        self.packet_type = packet_type

    def get_type(self):
        return self.packet_type

    def to_bytes(self):
        return pack("c", self.packet_type)

    def from_bytes(self, data):
        if calcsize(data) == 1:
            new_tuple = unpack("c", data)
            self.packet_type = new_tuple[0]
        else:
            new_tuple = unpack("cIHs", data)
            self.packet_type = new_tuple[0]


class File(Packet):

    def __init__(self, sequence_number, packet_type, payload):
        super().__init__(packet_type)
        self.packet_type = packet_type
        self.sequence_number = sequence_number
        self.payload = payload
        self.checksum = self.calculate_checksum()

    def calculate_checksum(self):
        data = str(self.sequence_number) + str(self.packet_type) + str(self.payload)
        return checksum_f(data)

    def to_bytes(self):
        return pack("cIHs", self.packet_type, self.sequence_number, self.checksum, self.payload)

    def from_bytes(self, data):
        new_tuple = unpack("cIHs", data)
        self.packet_type = new_tuple[0]
        self.sequence_number = new_tuple[0]
        self.checksum = new_tuple[0]
        self.payload = new_tuple[0]

