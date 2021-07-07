import os,sys,re
import time
import socket
import select

ip = "0.0.0.0"
udp_ports = [666, 6081, 888]
tcp_ports = [23, 8080]

# tcpSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# udpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
# geneve_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

udpSockets = {}
for port in udp_ports:
    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSocket.bind((ip, port))
    udpSockets[port] = udpSocket

tcpSockets = {}
for port in tcp_ports:
    tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    tcpSocket.bind((ip, port))
    tcpSockets[port] = tcpSocket
    tcpSocket.listen()

print("UDP server up and listening...")
s_list = list(udpSockets.values()) + list(tcpSockets.values())
while True:
    socket, _, _ = select.select(s_list, [], [])
    for s in socket:
        if s == udpSockets[666]:
            print("UDP:666")
            bytesAddressPair = s.recvfrom(1024)

            message = bytesAddressPair[0]
            address = bytesAddressPair[1]
            print("message:", message)
            print("address:", address)
            byte_str = "[Pytest]UDP:666 is back!".encode()
            s.sendto(byte_str, address)

        elif s == udpSockets[6081]:
            print("UDP:6081")
            bytesAddressPair = s.recvfrom(1024)

            message = bytesAddressPair[0]
            address = bytesAddressPair[1]
            print("message:", message)
            print("address:", address)
            byte_str = "[Pytest]UDP:6081 is back!".encode()
            byte_str += message
            s.sendto(byte_str, address)

        elif s == udpSockets[888]:
            print("UDP:888")
            bytesAddressPair = s.recvfrom(1024)

            message = bytesAddressPair[0]
            address = bytesAddressPair[1]
            print("message:", message)
            print("address:", address)
            byte_str = "[Pytest]UDP:888 is back!".encode()
            s.sendto(byte_str, address)

        elif s == tcpSockets[23]:
            print("TCP:23")
            clientConnection, clientAddress = s.accept()
            print("address:", clientAddress)

            data = clientConnection.recv(1024)
            print("data:", data)

            byte_str = "[Pytest]TCP:23 is back!".encode()
            clientConnection.send(byte_str)

        elif s == tcpSockets[8080]:
            print("TCP:8080")
            clientConnection, clientAddress = s.accept()
            print("address:", clientAddress)

            data = clientConnection.recv(1024)
            print("data:", data)

            byte_str = "[Pytest]TCP:8080 is back!".encode()
            clientConnection.send(byte_str)

        elif s == tcpSockets[80]:
            print("TCP:80")
            clientConnection, clientAddress = s.accept()
            print("address:", clientAddress)

            data = clientConnection.recv(1024)
            print("data:", data)

            byte_str = "[Pytest]TCP:80 is back!".encode()
            clientConnection.send(byte_str)