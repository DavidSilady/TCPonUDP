import ntpath
import os
import socket
import sys
import time
from threading import Thread, Event
from packet import *

TOTAL_HEADER_SIZE = 35

sock = socket.socket(socket.AF_INET,  # Internet
	                    socket.SOCK_DGRAM)  # UDP

UDP_IP = socket.gethostbyname(socket.gethostname())
UDP_PORT = 35000
sock.bind((UDP_IP, UDP_PORT))
BUFFER_SIZE = 1465

TARGET_IP = ""
TARGET_PORT = 0

IS_FILE = False
FILE_NAME = ""
FAULTY_INDEX = 2
RTT = 2
MAX_THREAD_COUNT = 20
THREAD_STOP = []
THREAD_COUNT = 1
TIMEOUT = []
BUFFER = []
SERVER_BUFFER = []


def send_first(num_packets, packet_type='h', payload=""):
	first = Content(num_packets, packet_type, payload.encode())  # H - Header
	sock.sendto(first.to_bytes(), (TARGET_IP, TARGET_PORT))


# https://stackoverflow.com/a/30239138
def multi_line_input():
	lines = []
	while True:
		line = input()
		if line == ":send":
			break
		else:
			lines.append(line)
	return '\n'.join(lines)
# end of stack overflow code


def send_text():
	print(TARGET_IP, TARGET_PORT)
	print("Message:")
	message = multi_line_input()
	# https://stackoverflow.com/questions/7286139/using-python-to-break-a-continuous-string-into-components/7286244#7286244
	chunks = [message[i:i + BUFFER_SIZE] for i in range(0, len(message), BUFFER_SIZE)]
	# end of stack overflow code
	packets = [Content(seq_num, 'm', chunk.encode()) for seq_num, chunk in enumerate(chunks)]
	global SERVER_BUFFER
	SERVER_BUFFER = chunks
	send_first(len(packets))
	queue_packets(packets)


def queue_packets(packets):

	global THREAD_COUNT
	THREAD_STOP.clear()
	TIMEOUT.clear()
	for packet in packets:
		while THREAD_COUNT > MAX_THREAD_COUNT:
			#print("Max Threads", THREAD_COUNT)
			time.sleep(0.05)
		send_t = Thread(target=sender_thread, args=[packet], daemon=True)
		event = Event()
		TIMEOUT.append(event)
		THREAD_STOP.append(False)
		THREAD_COUNT += 1
		send_t.start()
	print("---Sent---")


def sender_thread(packet):
	b_packet = packet.to_bytes()
	faulty = True
	while not THREAD_STOP[packet.sequence_number]:
		# print("Sending:", packet.sequence_number)
		if packet.sequence_number == FAULTY_INDEX and faulty:
			fault = packet
			fault.payload = b'\x00\x00'
			f_packet = fault.to_bytes()
			faulty = False
			sock.sendto(f_packet, (TARGET_IP, TARGET_PORT))
			print("Faulty packet", packet.sequence_number, "sent.")
		else:
			sock.sendto(b_packet, (TARGET_IP, TARGET_PORT))
	#		print("Packet", seq_num, "sent.")
		TIMEOUT[packet.sequence_number].wait(RTT)
	return


def send_file():

	packets = []
	path = input("Path to file: ")
	seq_num = 0
	start = time.time()
	with open(path, "rb") as file:
		chunk = file.read(BUFFER_SIZE)
		while chunk != b"":
			packet = Content(seq_num, 'f', chunk)
			seq_num += 1
			packets.append(packet)
			chunk = file.read(BUFFER_SIZE)
	global SERVER_BUFFER
	SERVER_BUFFER = [packet.payload for packet in packets]
	file_name = ntpath.basename(path)
	send_first(len(packets), 'H', file_name)
	queue_packets(packets)
	end = time.time()
	print("Time elapsed:", end - start, "s")
	return


def send_data():
	print("---Text/File---")
	command = input()
	if command == ":text":
		send_text()
	elif command == ":file":
		send_file()
	elif command == ":back":
		print("---User Interface---")
		return


def command_listener():
	print(UDP_IP, UDP_PORT, "LISTENING")
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
			print("Current size:", BUFFER_SIZE)
			new_size = int(input("New buffer (payload) size: "))
			if 1 < new_size < 1465:
				BUFFER_SIZE = new_size
			elif new_size < 1:
				BUFFER_SIZE = 1
				print("Size set to minimum (1)")
			else:
				BUFFER_SIZE = 1465
				print("Size set to maximum (1465)")
			sock.sendto(Response(BUFFER_SIZE, 'b').to_bytes(), (TARGET_IP, TARGET_PORT))
		elif command == ":clear":
			global THREAD_STOP
			THREAD_STOP.clear()
			BUFFER.clear()
			SERVER_BUFFER.clear()
			TIMEOUT.clear()
		elif command == ":listen":
			connect_listener = Thread(target=listen_for_connect, daemon=True)
			connect_listener.start()
		else:
			print("---Unknown Command---")


def connect():
	global TARGET_IP
	TARGET_IP = input("IP: ")
	global TARGET_PORT
	TARGET_PORT = int(input("Port: "))
	three_way_handshake()


def recv_hello():
	global RTT
	start = time.time()
	packet = Packet('y')
	sock.sendto(packet.to_bytes(), (TARGET_IP, TARGET_PORT))
	print("Sent greetings to", TARGET_IP, TARGET_PORT)
	data, addr = sock.recvfrom(BUFFER_SIZE + TOTAL_HEADER_SIZE)
	packet = Packet.from_bytes(data)
	if packet.packet_type == 'Y':
		sock.sendto(Packet('c').to_bytes(), (TARGET_IP, TARGET_PORT))
		end = time.time()
		RTT = (end - start) + 0.2
		listen_thread = Thread(target=listen, daemon=True)
		listen_thread.start()
		print("Connection successful.")
	else:
		print("Connection unsuccessful.")


def three_way_handshake():
	thread = Thread(target=recv_hello, daemon=True)
	thread.start()


def send_ack(seq_num, addr):
	response = Response(seq_num, 'a').to_bytes()
	sock.sendto(response, addr)


def send_nak(seq_num, addr):
	response = Response(seq_num, 'n').to_bytes()
	sock.sendto(response, addr)


def send_alive(addr):
	packet = Packet('l').to_bytes()  # live
	sock.sendto(packet, addr)


def merge_buffer():
	return b''.join(BUFFER)


def build_file(complete):
	path = os.getcwd()
	path = path + "/output/"
	try:
		os.mkdir(path)
	except FileExistsError:
		pass
	f = open(path + FILE_NAME, 'wb+')
	f.write(complete)
	f.close()
	print("File written in", path)
	pass


def handle_content(data, addr):
	try:
		global IS_FILE
		packet = Content.from_bytes(data)
		if packet.checksum == 0:
			if not BUFFER[packet.sequence_number] is None:
				send_ack(packet.sequence_number, addr)
				return
		#	print("Chunk:", packet.sequence_number)
			send_ack(packet.sequence_number, addr)
			BUFFER[packet.sequence_number] = packet.payload
			if not BUFFER.__contains__(None):
				print(BUFFER)
				complete = merge_buffer()
				BUFFER.clear()
				if IS_FILE:
					build_file(complete)
					IS_FILE = False
				else:
					complete = complete.decode()
					print(complete)
		else:
			send_nak(packet.sequence_number, addr)
	except IndexError:
		packet = Content.from_bytes(data)
	#	print(packet.sequence_number, packet.payload, "Index out.")
		send_ack(packet.sequence_number, addr)


def handle(data, addr):
	global BUFFER_SIZE
	global BUFFER
	global THREAD_COUNT

	packet = Packet.from_bytes(data)
	packet_type = packet.packet_type

	#print("\n/--------------------------------------------------\\")
	if packet_type == 'm' or packet_type == 'f':  # message or file
		handle_content(data, addr)
	elif packet_type == 'a' or packet_type == 'n':  # ACK or NAK
		packet = Response.from_bytes(data)
		if packet_type == 'a':
			THREAD_STOP[packet.sequence_number] = True
			TIMEOUT[packet.sequence_number].set()
			THREAD_COUNT -= 1
		else:
			print("Type:", packet.packet_type, packet.sequence_number)
			TIMEOUT[packet.sequence_number].set()
			TIMEOUT[packet.sequence_number].clear()
	elif packet_type == 'k':  # keep alive
		send_alive(addr)
	elif packet_type == 'l':  # alive
		print("Partner alive.")
	elif packet_type == 'h':  # header
		packet = Content.from_bytes(data)
		if packet.checksum == 0:
			BUFFER.clear()
			BUFFER = [None] * packet.sequence_number
			print("Receiving", packet.sequence_number, "packets. . .")
	elif packet_type == 'H':  # file header
		packet = Content.from_bytes(data)
		if packet.checksum == 0:
			global IS_FILE
			global FILE_NAME
			IS_FILE = True
			FILE_NAME = packet.payload.decode()
			print(FILE_NAME)
			BUFFER.clear()
			BUFFER = [None] * packet.sequence_number
			print("Receiving", packet.sequence_number, "packets. . .")
	elif packet_type == 'b':
		packet = Response.from_bytes(data)
		BUFFER_SIZE = packet.sequence_number
		print("New buffer size", BUFFER_SIZE)
	else:
		print("Unknown type")
	#print("\\--------------------------------------------------/\n")


def listen():
	while True:
		data, addr = sock.recvfrom(BUFFER_SIZE + TOTAL_HEADER_SIZE)  # total header size is 35
		if data:
			handle(data, addr)


def listen_for_connect():
	listening = True
	while listening:
		data, addr = sock.recvfrom(BUFFER_SIZE + TOTAL_HEADER_SIZE)  # total header size is 35
		if data:
			packet = Packet.from_bytes(data).packet_type
			if packet == 'y':
				sock.sendto(Packet('Y').to_bytes(), addr)
				print("Sent Y")
			if packet == 'c':
				listen_thread = Thread(target=listen, daemon=True)
				listen_thread.start()
				listening = False
				print("Connected to", addr)
			else:
				print("Unknown Packet", packet)


command_listener()
