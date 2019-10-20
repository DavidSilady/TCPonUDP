import socket
import sys
import time
import threading
from multiprocessing import Process
from threading import Thread

from packet import *

TOTAL_HEADER_SIZE = 35

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

BUFFER_SIZE = 8

sock = socket.socket(socket.AF_INET,  # Internet
	                    socket.SOCK_DGRAM)  # UDP
sock.bind((UDP_IP, UDP_PORT))

TARGET_IP = "127.0.0.1"
TARGET_PORT = 5005

RTT = 3

thread_stop = []
BUFFER = []


def send_first(num_packets):
	first = Response(num_packets, 'H')  # H - Header
	sock.sendto(first.to_bytes(), (TARGET_IP, TARGET_PORT))


def send_text():
	message = input("Message: ")
	# https://stackoverflow.com/questions/7286139/using-python-to-break-a-continuous-string-into-components/7286244#7286244
	chunks = [message[i:i + BUFFER_SIZE] for i in range(0, len(message), BUFFER_SIZE)]
	packets = [Content(seq_num, 'm', chunk) for seq_num, chunk in enumerate(chunks)]

	send_first(len(packets))
	for packet in packets:
		send_t = Thread(target=send_thread, args=[packet], daemon=True)
		thread_stop.append(False)
		send_t.start()
	print("---Sent---")


def send_thread(packet):
	b_packet = packet.to_bytes()
	while not thread_stop[packet.sequence_number]:
		sock.sendto(b_packet, (TARGET_IP, TARGET_PORT))
		time.sleep(RTT)
	return


def send_file():
	num_bytes = BUFFER_SIZE
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
			global BUFFER_SIZE
			BUFFER_SIZE = int(input("New buffer size: "))
		elif command == ":clear":
			global thread_stop
			thread_stop.clear()
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


def merge_buffer(complete=""):
	global BUFFER
	for chunk in BUFFER:
		complete += chunk
	return complete


def handle(data, addr):
	packet = Packet.from_bytes(data)
	packet_type = packet.packet_type
	global BUFFER
	print("\n/--------------------------------------------------\\")
	if packet_type == 'm' or packet_type == 'f':  # message or file
		packet = Content.from_bytes(data)
		if packet.checksum == 0:
			print("Chunk:", packet.payload)
			send_ack(packet.sequence_number, addr)
			BUFFER[packet.sequence_number] = packet.payload
			if packet.sequence_number == len(BUFFER) - 1:
				complete = merge_buffer()
				BUFFER.clear()
				print("Message:", complete)

		else:
			send_nak(packet.sequence_number, addr)
	elif packet_type == 'a' or packet_type == 'n':  # ACK or NAK
		packet = Response.from_bytes(data)
		print("Type:", packet.packet_type, packet.sequence_number)
		thread_stop[packet.sequence_number] = True
	elif packet_type == 'k':  # keep alive
		send_alive(addr)
	elif packet_type == 'l':
		print("Partner alive.")
	elif packet_type == 'H':
		packet = Response.from_bytes(data)
		BUFFER.clear()
		BUFFER = [None] * packet.sequence_number
	else:
		print("Unknown type")
	print("\\--------------------------------------------------/\n")


def listen():
	while True:
		data, addr = sock.recvfrom(BUFFER_SIZE + TOTAL_HEADER_SIZE)  # buffer size is 1024
		if data:
			handle(data, addr)


listen_thread = Thread(target=listen, daemon=True)
listen_thread.start()

command_listener()
