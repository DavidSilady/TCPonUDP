import socket
import sys
import time
import threading
from threading import Thread
from packet import Packet

UDP_IP = "127.0.0.1"
UDP_PORT = 5006

sock = socket.socket(socket.AF_INET,  # Internet
	                    socket.SOCK_DGRAM)  # UDP
sock.bind((UDP_IP, UDP_PORT))

TARGET_IP = "127.0.0.1"
TARGET_PORT = 5006


def send_text():
	message = input("Message: ")
	byte_message = str.encode(message)
	sock.sendto(byte_message, (TARGET_IP, TARGET_PORT))


def send_file():
	num_bytes = 1024
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
		send_file()
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
		else:
			print(command)


def listen():
	while True:
		data, addr = sock.recvfrom(1024)  # buffer size is 1024
		message = data.decode()
		print("Received message: ", message)


listen_thread = Thread(target=listen, daemon=True)
listen_thread.start()

command_listener()
