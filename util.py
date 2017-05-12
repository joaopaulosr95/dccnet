# !/usr/bin/python
# coding=utf-8

"""
Joao Paulo Sacchetto Ribeiro Bastos
2013073440

Trabalho pratico 1
01-05-2017
"""

import logging
import socket
import struct
import time


"""
The above code implements DCCNET protocol
DCCNET packets are built using the following structure

+-------------++-------------++---------++---------++-------+++-------+++-- ... --++++++++++
0  DCCNETC2   32  DCCNETC2   64 CHKSUM  80 LENGTH  96   ID  104 Flags 112   DATA  112+length
+-------------++-------------++---------++---------++-------+++-------+++---------++++++++++

First bit |   Last bit  | Meaning
----------+-------------+---------------------------------------------------------
	 00   |  32         | Sync flag
	 32   |  64         | Sync flag
	 64   |  80         | Checksum
	 80   |  96         | Length of data in packet
	 96   |  104        | Package ID
	104   |  112        | Header flags (ACK, no more data)
	112   |  112+length | Data in packet
"""

MAX_CONN = 1  # max connections our program can handle
TIMEOUT = 1.0  # timeout in seconds before send same packet again
MTU = 2 ** 10 - 1  # max bytes size for packet
HEADER_FORMAT = "!LLHHBB"  # byte format string for a header to be packed
SYNC = "dcc023c2"  # sync header field "dc c0 23 c2"

"""
| ===================================================================
| Logging setup
| ===================================================================
"""
logging.basicConfig(level=logging.DEBUG,
					format="[%(asctime)s][%(levelname)s]%(message)s",
					datefmt="%m-%d-%Y %I:%M:%S %p")

"""
| ===================================================================
| Helper function
| ===================================================================
| Returns usage options for program
"""

def helper():
	exit("Run options:\n" +
		 "Server \t./dcc023c2.py -s <port> <input> <output>\n" +
		 "Client \t./dcc023c2.py -c <ip>:<port> <input> <output>\n" +
		 "In both calls <port> must be between 51000 and 55000")

"""
| ===================================================================
| Checksum calculator
| ===================================================================
"""

def checksum(data):
	if len(data) & 1:
		data = data + "0"

	s = 0
	for i in range(0, len(data), 2):
		w = ord(data[i]) + (ord(data[i + 1]) << 8)
		s = ((s + w) & 0xffff) + ((s + w) >> 16)

	return ~s & 0xffff

"""
| ===================================================================
| Package packer
| ===================================================================
| Takes some data and builds a DCCNET packet to be sent
|
| IMPORTANT: Despite HEADER_FORMAT refers to hex, we must
| convert it to byte sequence
"""

def pack(packet):
	hex_sync = int(SYNC, 16)

	# Here we map sync from a string array to a byte array in order to create our header
	header = struct.pack(HEADER_FORMAT, hex_sync, hex_sync, 0, packet["length"], packet["id"], packet["flags"])

	# Then we calculate the checksum of our header
	c = checksum(header + packet["data"])

	# Finally we create out packet
	return c, struct.pack(HEADER_FORMAT, hex_sync, hex_sync, c, packet["length"], packet["id"], packet["flags"])

"""
| ===================================================================
| Packet sender
| ===================================================================
| Here we take a packet and try to send it through the socket and
| catch the ACK after this
"""

def interact(sock, packet=None):
	while True:
		sock.send(packet)
		sock.settimeout(TIMEOUT)
		try:
			ack_first_byte = sock.recv(1)
			sock.settimeout(None)
			if ack_first_byte:
				break
		except socket.timeout:
			pass
		except socket.error:
			raise socket.error

	return ack_first_byte

"""
| ===================================================================
| Packet watcher
| ===================================================================
| Here we watch the network looking for bytes and try to build packets
| from them
"""

def watcher(sock, output_fh, ack_first_byte=None):
	prev_header_field = 0  # Header field num we are looking for
	prev_state = 0  # Byte position inside header field
	prev_buffer = ""  # Aux var for packet processing

	# Receive bytes from network and try to make a packet of them
	try:
		while prev_header_field < 7:

			# Check if we are in the middle of an ACK processing because we just sent a packet or not
			if ack_first_byte:
				recv_byte = ack_first_byte
				ack_first_byte = None
			else:
				recv_byte = sock.recv(1)

			output_fh.write(recv_byte)

			# Now were gonna look for two valid and consecutive sync fields - 4 bytes each
			if prev_header_field in (0, 1):
				if (prev_state == 0 and recv_byte == "\xdc") \
						or (prev_state == 1 and recv_byte == "\xc0") \
						or (prev_state == 2 and recv_byte == "#") \
						or (prev_state == 3 and recv_byte == "\xc2"):
					prev_buffer += recv_byte
					if prev_state == 3:
						prev_header_field += 1
						prev_buffer = ""
						prev_state = 0
					else:
						prev_state += 1
				else:
					prev_header_field = 0
					prev_state = 0

			# Checksum and length fields - 2 bytes each
			elif prev_header_field in (2, 3):
				prev_buffer += recv_byte
				if prev_state == 1:
					if prev_header_field == 2:
						recv_checksum = struct.unpack("!H", prev_buffer)[0]
					else:
						recv_length = struct.unpack("!H", prev_buffer)[0]
					prev_header_field += 1
					prev_buffer = ""
					prev_state = 0
				else:
					prev_state += 1

			# Id and flags fields - 1 byte each
			elif prev_header_field in (4, 5):
				if prev_header_field == 4:
					recv_id = struct.unpack("!B", recv_byte)[0]
				else:
					recv_flags = struct.unpack("!B", recv_byte)[0]
					if recv_flags & 0x3f or (recv_flags & 0x80 and recv_flags & 0x40):
						logging.error("Invalid packet flags! Dropping packet and looking for a new one.")

						# Drop the packet and restart process
						prev_header_field = 0
						prev_state = 0
						prev_buffer = ""
					elif recv_length == 0:
						break
				prev_header_field += 1
				prev_state = 0

			# Here we collect the data field (if any)
			elif recv_length > 0:
				if prev_state < recv_length:
					prev_buffer += recv_byte
					prev_state += 1
				if prev_state == recv_length:
					prev_header_field += 1
					prev_state = 0
					break

		return {"checksum": recv_checksum,
				"length": recv_length,
				"id": recv_id,
				"flags": recv_flags,
				"data": prev_buffer if recv_length > 0 else ""}
	except socket.error:
		raise socket.error

"""
| ===================================================================
| dccnet service
| ===================================================================
| Here is the actual logic of our protocol. This method acts as a
| controller of out actions
"""

def dccnet_service(sock, input_fh, output_fh):
	recv_thread = {
		"recv_no_more": False, # Has a packet with flag END been received?
		"last_sent": {"checksum": None, "length": None, "id": None, "flags": None, "data": None, "packet": None},
		"last_recv": {"checksum": None, "length": None, "id": 1, "flags": None, "data": None, "packet": None},
	}
	send_thread = {
		"send_no_more": False, # Is there any more data in my input file?
		"last_sent": {"checksum": None, "length": None, "id": 0, "flags": None, "data": None, "packet": None},
		"last_recv": {"checksum": None, "length": None, "id": None, "flags": None, "data": None, "packet": None},
		"waiting_ack": False # Did I just sent a data packet?
	}

	# As soon as we call dccnet_service we will send a packet to the other side
	try:
		prev_buffer = input_fh.read(MTU)
		if not prev_buffer:
			raise IOError
	except IOError:
		logging.warning("No data to read from input file. Will send an empty packet.")
		prev_buffer = ""

	# If the contents read are less in length then MTU, we won't bother reading the input file again
	send_thread["send_no_more"] = True if len(prev_buffer) < MTU else False

	pack_to_send = {
		"length": len(prev_buffer),
		"id": 0,
		"flags": 0x40 if send_thread["send_no_more"] else 0x00,  # 0x40 means END flag
		"data": prev_buffer
	}
	pack_to_send["checksum"], header = pack(pack_to_send)
	pack_to_send["packet"] = header + pack_to_send["data"]
	prev_buffer = ""

	try:
		ack_first_byte = interact(sock, pack_to_send["packet"])
	except socket.error:
		raise socket.error

	# Here we keep track of last sent packet
	send_thread["last_sent"], pack_to_send = pack_to_send, None

	logging.info("[THREAD-S][SEND][DATA]" \
				 + "[Checksum: {:5d}]".format(send_thread["last_sent"]["checksum"]) \
				 + "[Length: {:5d}]".format(send_thread["last_sent"]["length"]) \
				 + "[ID: {:1d}]".format(send_thread["last_sent"]["id"]) \
				 + "[Flags: {:3d}]".format(send_thread["last_sent"]["flags"]))

	# Flip 'ready to send' <==> 'waiting'
	send_thread["waiting_ack"] = True

	while True:

		# If our threads have nothing more to do we can end transmission
		if recv_thread["recv_no_more"] and not send_thread["waiting_ack"] and send_thread["send_no_more"]:
                        time.sleep(2.0)
			break

		# Try to fetch some new data if threads are still able to receive it
		sock.settimeout(TIMEOUT)
		try:
			recv_packet = watcher(sock, output_fh, ack_first_byte)
			ack_first_byte = None
			sock.settimeout(None)
		except socket.error:
			raise socket.error

		# Now we validate the checksum before processing the packet
		recalc_checksum, decoded_packet = pack(recv_packet)
		valid_checksum = recalc_checksum == recv_packet["checksum"]
		if valid_checksum:

			"""
			| '-c' thread |  do  | subject | '-s' thread |
			|-------------|------|---------|-------------|
			|      T0     | send |  data   |     T0      |
			|      T0     | recv |  ack    |     T0      |
			|      T1     | recv |  data   |     T1      |
			|      T1     | send |  ack    |     T1      |
			"""

			# ACK
			if recv_packet["flags"] == 0x80 and recv_packet["length"] == 0:

				# First ACK for last packet - Collect new data and send
				if send_thread["waiting_ack"] and recv_packet["id"] == send_thread["last_sent"]["id"]:
					logging.info("[THREAD-S][RECV][ACK ]" \
								 + "[Checksum: {:5d}]".format(recv_packet["checksum"]) \
								 + "[Length: {:5d}]".format(recv_packet["length"]) \
								 + "[ID: {:1d}]".format(recv_packet["id"]) \
								 + "[Flags: {:3d}]".format(recv_packet["flags"]))

					send_thread["waiting_ack"] = False

					# Check if there's still data to be sent
					if not send_thread["send_no_more"]:
						try:
							prev_buffer = input_fh.read(MTU)
							if not prev_buffer:
								raise IOError
						except IOError:
							logging.warning(
								"[THREAD-S] No more data to read from input file. Will send an empty packet.")
							prev_buffer = ""

						# If the contents read are less in length then MTU, we won't read the input file again
						send_thread["send_no_more"] = True if len(prev_buffer) < MTU else False

						# Here we keep track of last sent packet
						pack_to_send = {
							"length": len(prev_buffer),
							"id": (recv_packet["id"] + 1) % 2,
							"flags": 0x40 if send_thread["send_no_more"] else 0x00,  # 0x40 means END flag
							"data": prev_buffer
						}
						pack_to_send["checksum"], header = pack(pack_to_send)
						pack_to_send["packet"] = header + pack_to_send["data"]
						prev_buffer = ""

						try:
							ack_first_byte = interact(sock, pack_to_send["packet"])
						except socket.error:
							raise socket.error

						# Here we keep track of last sent packet
						send_thread["last_sent"], pack_to_send = pack_to_send, None

						logging.info("[THREAD-S][SEND][DATA]" \
									 + "[Checksum: {:5d}]".format(send_thread["last_sent"]["checksum"]) \
									 + "[Length: {:5d}]".format(send_thread["last_sent"]["length"]) \
									 + "[ID: {:1d}]".format(send_thread["last_sent"]["id"]) \
									 + "[Flags: {:3d}]".format(send_thread["last_sent"]["flags"]))

						send_thread["waiting_ack"] = True

				# send_thread is not waiting for an ACK because already received one for last sent packet
				elif not send_thread["waiting_ack"] and recv_packet["id"] == send_thread["last_sent"]["id"] \
						and recv_packet["checksum"] == send_thread["last_sent"]["checksum"]:
					logging.info("[THREAD-S][RETR][DATA]" \
								 + "[Checksum: {:5d}]".format(send_thread["last_sent"]["checksum"]) \
								 + "[Length: {:5d}]".format(send_thread["last_sent"]["length"]) \
								 + "[ID: {:1d}]".format(send_thread["last_sent"]["id"]) \
								 + "[Flags: {:3d}]".format(send_thread["last_sent"]["flags"]) \
								 + " Repeated/wrong ACK")
					try:
						ack_first_byte = interact(sock, send_thread["last_sent"]["packet"])
					except socket.error:
						raise socket.error

			# Its just some data, lets send an ACK
			elif not recv_packet["flags"] == 0x80:

				# Here we keep track of last received packet
				recv_thread["last_recv"] = recv_packet

				recv_thread["recv_no_more"] = recv_packet["flags"] == 0x40

				logging.info("[THREAD-R][RECV][DATA]" \
							 + "[Checksum: {:5d}]".format(recv_packet["checksum"]) \
							 + "[Length: {:5d}]".format(recv_packet["length"]) \
							 + "[ID: {:1d}]".format(recv_packet["id"]) \
							 + "[Flags: {:3d}]".format(recv_packet["flags"]))

				pack_to_send = {"length": 0, "id": recv_thread["last_recv"]["id"], "flags": 0x80, "data": ""}
				pack_to_send["checksum"], header = pack(pack_to_send)
				pack_to_send["packet"] = header

				try:
					ack_first_byte = interact(sock, pack_to_send["packet"])
				except socket.error:
					raise socket.error

				logging.info("[THREAD-R][SEND][ACK ]" \
							 + "[Checksum: {:5d}]".format(pack_to_send["checksum"]) \
							 + "[Length: {:5d}]".format(pack_to_send["length"]) \
							 + "[ID: {:1d}]".format(pack_to_send["id"]) \
							 + "[Flags: {:3d}]".format(pack_to_send["flags"]))

				# Here we keep track of last sent packet
				recv_thread["last_sent"], pack_to_send = pack_to_send, None

		else:
			logging.error("Wrong checksum field value! Dropping the packet.")
		prev_buffer = ""

	logging.info("End of transmission!")
