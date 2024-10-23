#!/usr/bin/env python3
from network_sim import monitor
Monitor = monitor.Monitor

import sys
import math

# Config File
import configparser

#STATIC VARIABLES
HEADER_SIZE = 8

def extract_seq_num(packet):
    return int.from_bytes(packet[:HEADER_SIZE], byteorder='big')

def create_ack(seq_num, message='ERR'):
    return seq_num.to_bytes(HEADER_SIZE, byteorder='big') + message

def receiver(config_path):
	print("Receiver starting up!")

	# Initialize sender monitor
	recv_monitor = Monitor(config_path, 'receiver')
	
	# Parse config file
	cfg = configparser.RawConfigParser(allow_no_value=True)
	cfg.read(config_path)
	sender_id = int(cfg.get('sender', 'id'))
	file_to_send = cfg.get('nodes', 'file_to_send')
	max_packet_size = int(cfg.get('network', 'MAX_PACKET_SIZE'))
	write_location = cfg.get('receiver', 'write_location')
	
	# Get network parameters
	prop_delay = float(cfg.get('network', 'PROP_DELAY'))
	link_bandwidth = int(cfg.get('network', 'LINK_BANDWIDTH'))
	random_drop_probability = float(cfg.get('network', 'RANDOM_DROP_PROBABILITY'))
	reorder_probability = float(cfg.get('network', 'REORDER_PROBABILITY'))

	#calculate window size
	window_size = link_bandwidth * prop_delay / max_packet_size
	window_size = math.ceil(window_size*(1+random_drop_probability+reorder_probability))

	rec_file = open(write_location, 'wb')
	packet_buffer = []
	last_seq_num = -1

	while(True):		
		# Receive packet
		addr, packet = recv_monitor.recv(max_packet_size + HEADER_SIZE)
		seq_num = extract_seq_num(packet)
		data = packet[HEADER_SIZE:]
		# print(f"Received packet with sequence number {seq_num}")

		if data == b'EOT':
			print("Received end-of-transmission packet " + str(seq_num))
			while packet_buffer and packet_buffer[0][0] == last_seq_num + 1:
				seq_num, data = packet_buffer.pop(0)
				rec_file.write(data)
				#print(f"Writing data to file with sequence number {seq_num}")
				last_seq_num += 1
			# Send ACK for last sequence number
			ack = create_ack(last_seq_num, b"C")
			recv_monitor.send(sender_id, ack)
			# print(f"Sent CACK for packet with sequence number {seq_num} from EOT section")
			#bug hunting
			if packet_buffer:
				print(f"Packet buffer is not empty: {len(packet_buffer)}")

			else:
				# Send ACK for EOT packet
				ack = create_ack(seq_num, b"E")
				recv_monitor.send(sender_id, ack)
				# recv_monitor.send(sender_id, ack)
				# recv_monitor.send(sender_id, ack)
				
				# Exit! Make sure the receiver ends before the sender. send_end will stop the emulator.
				rec_file.close()
				recv_monitor.recv_end(write_location, sender_id)
				break
		elif seq_num == last_seq_num + 1:
			rec_file.write(data)
			#print(f"Writing data to file with sequence number {seq_num}")
			last_seq_num += 1
			packet_buffer = [packet for packet in packet_buffer if packet[0] > last_seq_num]
			packet_buffer.sort(key=lambda x: x[0])
			for i in range(len(packet_buffer)):
				if packet_buffer[i][0] <= last_seq_num:
					packet_buffer.pop(i)
					i -= 1
				else:
					break

			while packet_buffer and packet_buffer[0][0] == last_seq_num + 1:
				seq_num, data = packet_buffer.pop(0)
				rec_file.write(data)
				#print(f"Writing data to file with sequence number {seq_num}")
				last_seq_num += 1
			ack = create_ack(last_seq_num, b"C")
			recv_monitor.send(sender_id, ack)
			# print(f"Sent CACK for packet with sequence number {seq_num}")
		elif seq_num < last_seq_num + 1:
			packet_buffer = [packet for packet in packet_buffer if packet[0] > last_seq_num]
			packet_buffer.sort(key=lambda x: x[0])
			for i in range(len(packet_buffer)):
				if packet_buffer[i][0] <= last_seq_num:
					packet_buffer.pop(i)
					i -= 1
				else:
					break

			while packet_buffer and packet_buffer[0][0] == last_seq_num + 1:
				seq_num, data = packet_buffer.pop(0)
				rec_file.write(data)
				#print(f"Writing data to file with sequence number {seq_num}")
				last_seq_num += 1
			print("Received duplicate packet, last_seq_num: " + str(last_seq_num) + " seq_num: " + str(seq_num))
			ack = create_ack(last_seq_num, b"D")
			recv_monitor.send(sender_id, ack)
			recv_monitor.send(sender_id, ack)
			recv_monitor.send(sender_id, ack)
			pass

		elif seq_num not in [x[0] for x in packet_buffer]:
			packet_buffer.append((seq_num, data))
			ack = create_ack(seq_num, b"S")
			recv_monitor.send(sender_id, ack)
			# print(f"Added packet with sequence number {seq_num} to buffer and sent SACk")
		else:
			print(f"BIG ERROR, received packet with sequence number {seq_num}")
		
		
if __name__ == "__main__":
	config_path = sys.argv[1]
	receiver(config_path)