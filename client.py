import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)


sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP


def send_text():
    message = input()
    byte_message = str.encode(message)
    sock.sendto(byte_message, (UDP_IP, UDP_PORT))


send_text()
