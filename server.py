import socket
import sys
import time
import threading
from multiprocessing import Process
from threading import Thread

from urllib3.connectionpool import xrange

from packet import *

TOTAL_HEADER_SIZE = 35

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

buffer_size = 1024

sock = socket.socket(socket.AF_INET,  # Internet
	                    socket.SOCK_DGRAM)  # UDP
sock.bind((UDP_IP, UDP_PORT))

TARGET_IP = "127.0.0.1"
TARGET_PORT = 5005


def send_text():
	message = input("Message: ")
	if message.__sizeof__() > buffer_size:
		# https://stackoverflow.com/questions/7286139/using-python-to-break-a-continuous-string-into-components/7286244#7286244
		chunks = [message[i:i+buffer_size] for i in xrange(0, len(message), buffer_size)]
		seq_num = 0
		for chunk in chunks:
			packet = Content(seq_num, 'm', chunk)
			seq_num += 1
			b_packet = packet.to_bytes()
			sock.sendto(b_packet, (TARGET_IP, TARGET_PORT))
	print("---Sent---")


def send_thread(b_packet):
	pass


def send_file():
	num_bytes = buffer_size
	path = input("Path to file: ")
	with open(path, "rb") as file:
		chunk = file.read(num_bytes)
		while chunk != b"":
			# Do stuff with chunk.
			chunk = file.read(num_bytes)
	return


def send_data():
	print("---Text/File---")
	command = input()
	if command == ":text":
		send_text()
	elif command == ":file":
		print("Nothing happens yet")
		# send_file()
	elif command == ":back":
		print("---User Interface---")
		return


def connect():
	global TARGET_IP
	TARGET_IP = input("IP: ")
	global TARGET_PORT
	TARGET_PORT = int(input("Port: "))


def command_listener():
	print("---User Interface---")
	while True:
		command = input()
		if command == ":quit":
			print("---Exiting Application---")
			sys.exit()
		elif command == ":send":
			print("---Send Data---")
			send_data()
		elif command == ":connect":
			connect()
		elif command == ":buffer":
			global buffer_size
			buffer_size = int(input("New buffer size: "))
		else:
			print("---Unknown Command---")


def send_ack(seq_num, addr):
	response = Response(seq_num, 'a').to_bytes()
	sock.sendto(response, addr)


def send_nak(seq_num, addr):
	response = Response(seq_num, 'n').to_bytes()
	sock.sendto(response, addr)


def send_alive(addr):
	packet = Packet('l').to_bytes()  # live
	sock.sendto(packet, addr)


def handle(data, addr):
	packet = Packet.from_bytes(data)
	packet_type = packet.packet_type

	print("Type:", packet.packet_type)

	if packet_type == 'm' or packet_type == 'f':  # message or file
		packet = Content.from_bytes(data)
		print("Message:", packet.payload, packet.sequence_number)
		if packet.checksum == 0:
			send_ack(packet.sequence_number, addr)
		else:
			send_nak(packet.sequence_number, addr)
	elif packet_type == 'a' or packet_type == 'n':  # ACK or NAK
		packet = Response.from_bytes(data)
	elif packet_type == 'k':  # keep alive
		send_alive(addr)
	elif packet_type == 'l':
		print("Partner alive.")
	else:
		print("Unknown type")


def listen():
	while True:
		data, addr = sock.recvfrom(buffer_size + TOTAL_HEADER_SIZE)  # buffer size is 1024
		if data:
			handle(data, addr)


listen_thread = Thread(target=listen, daemon=True)
listen_thread.start()

command_listener()
