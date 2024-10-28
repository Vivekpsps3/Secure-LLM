#!/usr/bin/env python3
from network_sim import monitor
Monitor = monitor.Monitor
import sys
import time
import math
import threading
import queue
import multiprocessing
import random
import binascii

# Config File
import configparser

#STATIC VARIABLES
HEADER_SIZE = 8
TIMEOUT = 1
MAX_WINDOW_SIZE = 1000

def get_file_contents(file_path):
	f = open(file_path, 'rb')
	file = f.read()
	f.close()
	return file
	
def create_packet(seq_num, data):
    return seq_num.to_bytes(HEADER_SIZE, byteorder='big') + data

def extract_seq_num(packet):
    return int.from_bytes(packet[:HEADER_SIZE], byteorder='big')

def generate_packet_list(file, max_packet_size):
	packet_list = []
	seq_num = 0
	offset = 0
	maxdata = max_packet_size - HEADER_SIZE - 4
	while offset < len(file):
		chunk = file[offset:offset+maxdata]
		# chunk = binascii.hexlify(chunk)
		packet = create_packet(seq_num, chunk)
		packet_list.append(packet)
		offset += maxdata
		seq_num += 1

	eot_packet = create_packet(seq_num, b'EOT')
	packet_list.append(eot_packet)

	return packet_list

class Sender:
	def __init__(self, cfg, config_path):
		# Get network parameters
		self.receiver_id = int(cfg.get('receiver', 'id'))
		self.file_to_send = cfg.get('nodes', 'file_to_send')
		# self.file_to_send = file_path = "network_sim/" + self.file_to_send
		self.max_packet_size = int(cfg.get('network', 'MAX_PACKET_SIZE'))
		self.send_monitor = Monitor(config_path, 'sender')
		self.prop_delay = float(cfg.get('network', 'PROP_DELAY'))
		self.link_bandwidth = int(cfg.get('network', 'LINK_BANDWIDTH'))
		self.random_drop_probability = float(cfg.get('network', 'RANDOM_DROP_PROBABILITY'))
		self.reorder_probability = float(cfg.get('network', 'REORDER_PROBABILITY'))

		# Calculate window size
		self.window_size = self.calculate_window_size()
		
		# Read file and generate packet list
		self.file = get_file_contents(self.file_to_send)
		self.packet_list = generate_packet_list(self.file, self.max_packet_size)
		self.ack_list = []
		self.sack_list = []
		self.retransmit_timer = {}
		self.RTT = 0.5
		self.final_packet_count = 0

		# Mutex locks
		self.lock = threading.Lock()

		self.start_time = time.time()
		# Acknowledgment tracking
		self.acknowledged = 0  # Cumulative ACK
		self.duplicate_ack_count = {}  # Fast retransmission tracker

	
	def send(self):
		maxdata = self.max_packet_size - HEADER_SIZE - 4

        # Thread 1: Sending Packets
		sender_thread = threading.Thread(target=self._sender_loop, args=(maxdata,))
		sender_thread.start() 

		# Thread 2: Receiving ACKs
		ack_thread = threading.Thread(target=self._ack_receiver)
		ack_thread.start()
		
		#timeout both threads after 15 seconds
		sender_thread.join(timeout=15)
		ack_thread.join(timeout=15)

	def _sender_loop(self, maxdata):
		seq_num = 0
		ctr = 0
		while not self.acknowledged == -1:
				# Send packets based on window size
			while seq_num < len(self.packet_list):
				time.sleep(0.001)
				with self.lock:
					#count SACKS between seq_num and self.acknowledged
					sack_count = 0
					for sack in self.ack_list:
						if sack > self.acknowledged:
							sack_count += 1
					
					if seq_num - self.acknowledged >= (self.window_size+ sack_count):
						break
					elif seq_num - self.acknowledged >= MAX_WINDOW_SIZE:
						break
					packet = self.packet_list[seq_num]
					self.sack_list.append(seq_num)
					self.retransmit_timer[seq_num] = time.time()
					
					# Send the packet
					self.send_monitor.send(self.receiver_id, packet)
					#print(f"Sender: Sending packet with seq_num {seq_num}.")
					
					# Track unacknowledged packets						
					seq_num += 1
			ctr += 1
			# Handle retransmissions
			#sleep for 0.05 seconds to clear the buffer
			time.sleep(0.001)
			# if continue_sending == False:
			# 	time.sleep(0.1)
			# if seq_num >= len(self.packet_list) * 0.05 and ctr % 3 == 0:
			# 	continue_sending = self._retransmit(seq_num)
			# elif seq_num > len(self.packet_list) * 0.7 and ctr % 2 == 0:
			# 	continue_sending = self._retransmit(seq_num)
			# elif seq_num >= len(self.packet_list) * 0.95:
			# 	continue_sending = self._retransmit(seq_num)
			# else:
			# 	pass
				# time.sleep(0.16)
				# time_end = time.time() - self.start_time
				# print(f"Time taken: {time_end}")
				# continue_sending = self._retransmit(seq_num)

			self._retransmit(seq_num)		
		
		# Send end-of-transmission packet
		# eot_packet = create_packet(seq_num, b'EOT')
		# self.send_monitor.send(self.receiver_id, eot_packet)
		# print("Sender: Sending end-of-transmission packet.")
	
	def _ack_receiver(self):
		while True:

			# Receive ACKs
			# time.sleep(0.001)
			addr, data = self.safe_timeout(self.max_packet_size)
			if data == "NONE":
				print("Sender: Timeout. Resending unacknowledged packets.")
				#force add all packets after the last acknowledged packet to the sack_list
				# with self.lock:
				# 	for i in range(self.acknowledged, len(self.packet_list)):
				# 		if i not in self.sack_list:
				# 			self.sack_list.append(i)

				self._retransmit()
				continue

			ack_num = extract_seq_num(data)				
			data = data[HEADER_SIZE:]
			data = data.decode().strip()

			self.RTT = 0.875 * self.RTT + 0.125 * (time.time() - self.retransmit_timer[ack_num])
			self.RTT = min(0.5, self.RTT)
			self.RTT = 0.5
			# print("Packet RTT is: ", time.time() - self.retransmit_timer[ack_num])
			if data == "S":
				# SACK received
				with self.lock:
					# Update SACK list
					# remove the seq_num from the sack_list
					if ack_num in self.sack_list:
						self.sack_list.remove(ack_num)
					self.ack_list.append(ack_num)
					# print(f"Sender: Received SACK for packets with seq_num {ack_num}.")
			elif data == "C":
				# Cumulative ACK received
				with self.lock:
					# Update cumulative ACK
					self.acknowledged = ack_num
					# print(f"Sender: Received CACK for packet with seq_num {ack_num}.")
					# Remove any SACKed packets from the SACK list less than the cumulative ACK
					self.sack_list = [x for x in self.sack_list if x > ack_num]
					self.ack_list = [x for x in self.ack_list if x > ack_num]
			elif data == "D":
				self.acknowledged = max(self.acknowledged, ack_num)
				self.sack_list = [x for x in self.sack_list if x > ack_num]
				self.ack_list = [x for x in self.ack_list if x > ack_num]
				pass
				
			elif data == "E":
				# End of transmission
				print("Sender: End of transmission Acknowledged.")
				self.sack_list = []
				self.ack_list = []
				self.acknowledged = -1
				self.exit()
				break
			if self.acknowledged == -1:
				self.exit()
				break

	def _retransmit(self, seq_num=None):

		# if seq_num == -1:
		# 	#retransmit all packets in the sack_list
		# 	time.sleep(0.001)
		# 	with self.lock:
		# 		self.sack_list.sort()
		# 	time.sleep(0.001)
		# 	for seq_num in self.sack_list:
		# 		time.sleep(0)
		# 		with self.lock:
		# 			if seq_num in self.retransmit_timer:
		# 				if time.time() - self.retransmit_timer[seq_num] < self.RTT:
		# 					continue
		# 			packet = self.packet_list[seq_num]
		# 			self.send_monitor.send(self.receiver_id, packet)
		# 			print(f"Sender: Retransmitting packet with seq_num {seq_num}.")
		# 			self.retransmit_timer[seq_num] = time.time()
					

		time.sleep(0.001)
		with self.lock:
			self.sack_list.sort()
		time.sleep(0.001)
		for seq_num in self.sack_list:
			time.sleep(0)
			with self.lock:
				if seq_num in self.retransmit_timer:
					if time.time() - self.retransmit_timer[seq_num] < (self.RTT * 1.5):
						continue
				packet = self.packet_list[seq_num]
				self.send_monitor.send(self.receiver_id, packet)
				print(f"Sender: Retransmitting packet with seq_num {seq_num}.")
				self.retransmit_timer[seq_num] = time.time()
				if seq_num == extract_seq_num(self.packet_list[-1]):
					self.final_packet_count += 1
					if self.final_packet_count > 5:
						print("Sender: Retransmitting last packet too many times. Exiting.")
						self.acknowledged = -1
						exit()

		
		
	def exit(self):
		# Exit! Make sure the receiver ends before the sender. send_end will stop the emulator.
		self.send_monitor.send_end(self.receiver_id)
		pass

	def safe_timeout(self, MAX_SIZE):
		# q = multiprocessing.Queue()
		q = queue.Queue()
		
		# Inner function to run the test and store result in queue
		def run_test():
			q.put(self.send_monitor.recv(MAX_SIZE))
		
		# Start the thread
		thread = threading.Thread(target=run_test)
		thread.start()
		
		# Wait for up to TIMEOUT seconds for thread to finish
		thread.join(timeout=TIMEOUT)

		# # Start the process
		# process = multiprocessing.Process(target=run_test)
		# process.start()

		# # Wait for up to TIMEOUT seconds for process to finish
		# process.join(timeout=TIMEOUT)

		
		# Return result if available, else return "NONE", "NONE"
		return q.get() if not q.empty() else ("NONE", "NONE")

	def calculate_window_size(self):
		window_size = self.link_bandwidth * self.prop_delay / self.max_packet_size
		window_size = math.ceil(window_size * (1 + self.random_drop_probability + self.reorder_probability))
		#multiply window size by 2.5 to increase the speed of the sender accounting for RTT and drop probability and reorder probability
		window_size = math.ceil(window_size * 2.5)
		return window_size
	
if __name__ == '__main__':
	print("Sender starting up!")
	config_path = sys.argv[1]

	# Parse config file
	cfg = configparser.RawConfigParser(allow_no_value=True)
	cfg.read(config_path)
	
	# Create sender object
	sender = Sender(cfg, config_path)
	sender.send()



