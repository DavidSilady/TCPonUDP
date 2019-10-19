from checksum_f import checksum_f
from struct import *


class Packet:
    def __init__(self, packet_type):
        self.packet_type: str = packet_type

    def get_type(self):
        return self.packet_type

    def to_bytes(self):
        return pack("!c", self.packet_type.encode('utf-8'))

    @classmethod
    def from_bytes(cls, data):
        if calcsize(data) == 1:
            new_tuple = unpack("!c", data)
            b_packet_type = new_tuple[0]
            packet_type = b_packet_type.decode()
        else:
            new_tuple = unpack("!cIH", data)
            b_packet_type = new_tuple[0]
            packet_type = b_packet_type.decode()
        return cls(packet_type)


class Response(Packet):

    def __init__(self, sequence_number, packet_type):
        super().__init__(packet_type)
        self.sequence_number: int = sequence_number

    def to_bytes(self):
        return pack("!cIH", self.packet_type.encode('utf-8'), self.sequence_number)

    @classmethod
    def from_bytes(cls, data):
        new_tuple = unpack("!cIH", data[:7])
        packet_type = new_tuple[0]
        sequence_number = new_tuple[1]
        return cls(sequence_number, packet_type)


class Message(Packet):

    def __init__(self, sequence_number, packet_type, payload, checksum=0):
        super().__init__(packet_type)
        self.sequence_number: int = sequence_number
        self.payload = payload
        self.checksum = self.calculate_checksum(checksum)

    def calculate_checksum(self, checksum=0):
        data = str(self.sequence_number) + str(self.packet_type) + str(self.payload)
        return checksum_f(data, checksum)

    def to_bytes(self):
        return pack("!cIH", self.packet_type.encode('utf-8'), self.sequence_number, self.checksum)\
               + str.encode(self.payload)

    @classmethod
    def from_bytes(cls, data):
        new_tuple = unpack("!cIH", data[:7])
        packet_type = new_tuple[0]
        sequence_number = new_tuple[1]
        checksum = new_tuple[2]
        payload = data[7:]
        return cls(sequence_number, packet_type.decode(), payload.decode(), checksum)

