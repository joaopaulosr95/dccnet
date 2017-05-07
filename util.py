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


MAX_CONN = 1  # max connections our program can handle
TIMEOUT = 1.0  # timeout in seconds before send same packet again
MAX_ATTEMPTS = 10
MTU = 2 ** 16 - 1  # max bytes size for packet
HEADER_FORMAT = "!LLHHBB"  # byte format string for a header to be packed
SYNC = "dcc023c2"  # sync header field "dc c0 23 c2"

"""
| ===================================================================
| Logging setup
| ===================================================================
"""
logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(levelname)s]: %(message)s",
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

"""
| ===================================================================
| Checksum calculator
| ===================================================================
"""

def checksum(data):
    if len(data) & 1:
        data = data + '0'

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
        try:
            sock.settimeout(TIMEOUT)
            ack_first_byte = sock.recv(1)
            if ack_first_byte:
                break
        except socket.timeout:
            time.sleep(TIMEOUT)

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
            elif prev_state == recv_length:
                prev_header_field += 1
                prev_state = 0
                break

    return {"checksum": recv_checksum,
            "length": recv_length,
            "id": recv_id,
            "flags": recv_flags,
            "data": prev_buffer if recv_length > 0 else ""}

"""
| ===================================================================
| dccnet service
| ===================================================================
| Here is the actual logic of our protocol. This method acts as a
| controller of out actions
"""

def dccnet_service(sock, input_fh, output_fh, active=False):
    last_sent = {"packet": None, "checksum": None, "length": None, "id": None, "flags": None, "data": None}
    last_recv = {"packet": None, "checksum": None, "length": None, "id": None, "flags": None, "data": None}
    send_no_more = False
    recv_no_more = False
    ack_first_byte = None

    # If program was called as 'active', then we need to make the first move and send a packet
    if active:
        prev_buffer = input_fh.read(MTU)
        if not prev_buffer:
            logging.warning("No contents found, check input file.")
            prev_buffer = ""

        # If the contents read are less in length then MTU, we won't bother reading the input file again
        send_no_more = True if not send_no_more and len(prev_buffer) < MTU else False
        last_sent = {"length": len(prev_buffer), "id": 0, "flags": 0x40 if send_no_more else 0x00, "data": prev_buffer}
        last_sent["checksum"], header = pack(last_sent)
        last_sent["packet"] = header + last_sent["data"]
        prev_buffer = ""

        ack_first_byte = interact(sock, last_sent["packet"])  # Send data

        logging.info("[SEND][DATA][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
            last_sent["checksum"], last_sent["length"], last_sent["id"], last_sent["flags"]))

    # Common behavior for both active and passive calls
    while True:
        if not recv_no_more:
            if active:
                recv_packet = watcher(sock, output_fh, ack_first_byte)
            else:
                recv_packet = watcher(sock, output_fh)
            recv_no_more = True if recv_packet["flags"] == 0x40 else False

        # Now we validate the checksum before processing the packet
        recalc_checksum, decoded_packet = pack(recv_packet)
        valid_checksum = recalc_checksum == recv_packet['checksum']
        if valid_checksum:

            # Wrong ACK format
            if recv_packet["flags"] & 0x80 and recv_packet["length"] != 0:
                logging.error(
                    "[RECV][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]. WRONG ACK FORMAT".format(
                        recv_packet["checksum"], recv_packet["length"], recv_packet["id"], recv_packet["flags"]))

            # Correct ACK format
            elif recv_packet["length"] == 0:
                logging.info("[RECV][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                    recv_packet["checksum"], recv_packet["length"], recv_packet["id"], recv_packet["flags"]))

                # First ACK for last packet - Collect new data and send
                if not send_no_more and recv_packet["id"] == last_sent["id"]:
                    try:
                        prev_buffer = input_fh.read(MTU)
                        if not prev_buffer:
                            raise IOError
                    except IOError:
                        logging.warning("Input file is over. Will send an empty packet.")
                        pass

                    # If the contents read are less in length then MTU, we won't bother reading the input file again
                    send_no_more = True if not send_no_more and len(prev_buffer) < MTU else False

                    # Here we keep track of last sent packet
                    last_sent = {"length": len(prev_buffer), "id": 1 if recv_packet["id"] == 0 else 0,
                                 "flags": 0x40 if send_no_more else 0x00, "data": prev_buffer}
                    last_sent["checksum"], header = pack(last_sent)
                    last_sent["packet"] = header + last_sent["data"]

                    ack_first_byte = interact(sock, last_sent["packet"])  # Send new data
                    logging.info("[SEND][DATA][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                        recv_packet["checksum"], recv_packet["length"], recv_packet["id"], recv_packet["flags"]))

                # Repeated ACK
                elif recv_packet["id"] == last_recv["id"]:
                    logging.warning("An error probably ocurred, I've received this ACK yet. Retransmitting...")

                    ack_first_byte = interact(sock, last_sent["packet"])
                    logging.info("[RETR][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                        recv_packet["checksum"], recv_packet["length"], recv_packet["id"], recv_packet["flags"]))

            # Just some data, lets send an ACK
            else:

                # Here we keep track of last received packet
                last_recv = recv_packet
                last_recv["packet"] = pack(last_recv)[1] + last_recv["data"]
                logging.info("[RECV][DATA][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                    recv_packet["checksum"], recv_packet["length"], recv_packet["id"], recv_packet["flags"]))

                # Here we keep track of last sent packet
                last_sent = {"checksum": recalc_checksum, "length": 0, "id": last_recv["id"], "flags": 0x80, "data": ""}
                last_sent["packet"] = pack(last_sent)[1]

                ack_first_byte = interact(sock, last_sent["packet"])  # Send the ACK
                logging.info("[SEND][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                    last_sent["checksum"], last_sent["length"], last_sent["id"], last_sent["flags"]))
        else:
            logging.error("Wrong checksum field value! Dropping the packet.")
        prev_buffer = ""

        if (active and send_no_more) or (not active and recv_no_more):
            break

    logging.info("End of transmission!")
