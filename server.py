import socket
import sys
import time
from concurrent.futures.thread import ThreadPoolExecutor
from threading import Thread, Event
from packet import *

TOTAL_HEADER_SIZE = 35

UDP_IP = "169.254.195.226"
UDP_PORT = 35000

BUFFER_SIZE = 100

sock = socket.socket(socket.AF_INET,  # Internet
	                    socket.SOCK_DGRAM)  # UDP
sock.bind((UDP_IP, UDP_PORT))

TARGET_IP = "169.254.195.226"
TARGET_PORT = 35000

IS_FILE = False
FILE_NAME = ""
FAULTY_INDEX = 2
RTT = 2
MAX_THREAD_COUNT = 100
THREAD_STOP = []
THREAD_COUNT = 1
TIMEOUT = []
BUFFER = []
SERVER_BUFFER = []


def send_first(num_packets):
	first = Response(num_packets, 'H')  # H - Header
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
	queue_packets(packets)


def queue_packets(packets):
	global THREAD_COUNT
	THREAD_STOP.clear()
	TIMEOUT.clear()
	send_first(len(packets))
	for packet in packets:
		while THREAD_COUNT > MAX_THREAD_COUNT:
			print("Max Threads", THREAD_COUNT)
			time.sleep(0.1)
		send_t = Thread(target=sender_thread, args=[packet], daemon=True)
		event = Event()
		TIMEOUT.append(event)
		THREAD_STOP.append(False)
		THREAD_COUNT += 1
		send_t.start()
	print("---Sent---")


def sender_thread(packet, seq_num=len(TIMEOUT) - 1):
	try:
		seq_num = packet.sequence_number
	except TypeError:
		print("Sending Last")
	b_packet = packet.to_bytes()
	faulty = True
	while not THREAD_STOP[seq_num]:
		# print("Sending:", packet.sequence_number)
		if seq_num == FAULTY_INDEX and faulty:
			fault = packet
			fault.payload = b'\x00\x00'
			f_packet = fault.to_bytes()
			faulty = False
			sock.sendto(f_packet, (TARGET_IP, TARGET_PORT))
			print("Faulty packet", seq_num, "sent.")
		else:
			sock.sendto(b_packet, (TARGET_IP, TARGET_PORT))
			print("Packet", seq_num, "sent.")
		TIMEOUT[seq_num].wait(RTT)
	return


def send_file():
	packets = []
	path = input("Path to file: ")
	seq_num = 0

	with open(path, "rb") as file:
		chunk = file.read(BUFFER_SIZE)
		while chunk != b"":
			packet = Content(seq_num, 'f', chunk)
			seq_num += 1
			packets.append(packet)
			chunk = file.read(BUFFER_SIZE)
	global SERVER_BUFFER
	SERVER_BUFFER = [packet.payload for packet in packets]
	queue_packets(packets)
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


def connect():
	global TARGET_IP
	TARGET_IP = input("IP: ")
	global TARGET_PORT
	TARGET_PORT = int(input("Port: "))
	sock.connect((TARGET_IP, TARGET_PORT))


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
			global THREAD_STOP
			THREAD_STOP.clear()
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


def merge_buffer():
	return b''.join(BUFFER)


def handle_content(data, addr):
	packet = Content.from_bytes(data)
	if packet.checksum == 0:
		print("Chunk:", packet.sequence_number)
		send_ack(packet.sequence_number, addr)
		BUFFER[packet.sequence_number] = packet.payload
		if not BUFFER.__contains__(None):
			print(BUFFER)
			print(merge_buffer())
			BUFFER.clear()
	else:
		print("Error: ", packet.payload, "|", SERVER_BUFFER[packet.sequence_number])  # debug
		send_nak(packet.sequence_number, addr)


def handle(data, addr):
	global BUFFER
	global THREAD_COUNT

	packet = Packet.from_bytes(data)
	packet_type = packet.packet_type

	print("\n/--------------------------------------------------\\")
	if packet_type == 'm' or packet_type == 'f':  # message or file
		handle_content(data, addr)
	elif packet_type == 'a' or packet_type == 'n':  # ACK or NAK
		packet = Response.from_bytes(data)
		print("Type:", packet.packet_type, packet.sequence_number)
		if packet_type == 'a':
			THREAD_STOP[packet.sequence_number] = True
			TIMEOUT[packet.sequence_number].set()
			THREAD_COUNT -= 1
		else:
			TIMEOUT[packet.sequence_number].set()
			TIMEOUT[packet.sequence_number].clear()
	elif packet_type == 'k':  # keep alive
		send_alive(addr)
	elif packet_type == 'l':  # alive
		print("Partner alive.")
	elif packet_type == 'H':  # header
		packet = Response.from_bytes(data)
		if packet.checksum == 0:
			BUFFER.clear()
			BUFFER = [None] * packet.sequence_number
			print("Receiving", packet.sequence_number, "packets. . .")
	elif packet_type == 'h':  # file header
		packet = Packet.from_bytes(data)
		if packet.checksum == 0:
			global IS_FILE
			global FILE_NAME
			IS_FILE = True
			FILE_NAME = packet.payload.decode()
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
