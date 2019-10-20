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

RTT = 2
MAX_THREAD_COUNT = 100
thread_stop = []
thread_count = 1
timeout = []
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
	thread_stop.clear()
	timeout.clear()
	send_first(len(packets))
	for packet in packets:
		while thread_count > MAX_THREAD_COUNT:
			print("Num_Threads", thread_count)
			time.sleep(0.2)
		send_t = Thread(target=send_thread, args=[packet], daemon=True)
		event = Event()
		timeout.append(event)
		thread_stop.append(False)
		global thread_count
		thread_count += 1
		send_t.start()
	print("---Sent---")


def send_thread(packet):
	b_packet = packet.to_bytes()
	while not thread_stop[packet.sequence_number]:
		# print("Sending:", packet.sequence_number)
		sock.sendto(b_packet, (TARGET_IP, TARGET_PORT))
		print("Packet", packet.sequence_number, "sent.")
		timeout[packet.sequence_number].wait(RTT)
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


def handle_content(data, addr):
	packet = Content.from_bytes(data)
	if packet.checksum == 0:
		print("Chunk:", packet.sequence_number)
		send_ack(packet.sequence_number, addr)
		BUFFER[packet.sequence_number] = packet.payload
		if packet.sequence_number == len(BUFFER) - 1:
			# complete = merge_buffer()
#			print(BUFFER)
			BUFFER.clear()
			# print("Message:", complete)
	else:
		print("Error: ", packet.payload, "|", SERVER_BUFFER[packet.sequence_number])  # debug
		send_nak(packet.sequence_number, addr)


def handle(data, addr):
	packet = Packet.from_bytes(data)
	packet_type = packet.packet_type
	global BUFFER
	print("\n/--------------------------------------------------\\")
	if packet_type == 'm' or packet_type == 'f':  # message or file
		handle_content(data, addr)
	elif packet_type == 'a' or packet_type == 'n':  # ACK or NAK
		packet = Response.from_bytes(data)
		print("Type:", packet.packet_type, packet.sequence_number)
		thread_stop[packet.sequence_number] = True
		timeout[packet.sequence_number].set()
		global thread_count
		thread_count -= 1
		'''
		if packet_type == 'a':
			thread_stop[packet.sequence_number] = True
		else:
			repeat_packet = SERVER_BUFFER[packet.sequence_number]
			send_t = Thread(target=send_thread, args=[repeat_packet], daemon=True)
			send_t.start()
			'''
	elif packet_type == 'k':  # keep alive
		send_alive(addr)
	elif packet_type == 'l':
		print("Partner alive.")
	elif packet_type == 'H':
		packet = Response.from_bytes(data)
		BUFFER.clear()
		BUFFER = [None] * packet.sequence_number
		print("Receiving", packet.sequence_number, "packets. . .")
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
