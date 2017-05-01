# !/usr/bin/python
# coding=utf-8

"""
Joao Paulo Sacchetto Ribeiro Bastos
2013073440

Trabalho pratico 1
01-05-2017
"""

import struct
import socket
import logging


HEADER_FORMAT = "!LLHHBB"  # byte format string for a header to be packed
SYNC = "dcc023c2"  # sync header field "dc c0 23 c2"

TIMEOUT = 1.0  # timeout in seconds before send same packet again
MAX_ATTEMPTS = 15

MTU = 2 ** 16  # max bytes size for packet

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
The above code implements DCCNET protocol over a TCP connection.
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

def carry_around_add(a, b):
    c = a + b

    return (c & 0xffff) + (c >> 16)

def checksum(data):
    if len(data) & 1:
        data = "0" + data

    s = 0
    for i in range(0, len(data), 2):
        w = ord(data[i]) + (ord(data[i + 1]) << 8)
        s = carry_around_add(s, w)

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
| Packet watcher
| ===================================================================
| Here we watch the network looking for packets and, depending of
| what is captured, we follow a path in order to accept data or
| process an ACK.
"""

def watcher(sock, input_fh, output_fh, active=False):
    # Here we keep track of last sent and received packages
    last_sent = {"packet": None, "checksum": None, "length": None, "id": None, "flags": None, "data": None}
    last_recv = {"packet": None, "checksum": None, "length": None, "id": None, "flags": None, "data": None}

    recv_attempts = 0  # Attempts of receiving a packet
    send_no_more = False
    recv_no_more = False
    end_transmission = False  # Indicates of peers are exchanging data

    prev_header_field = 0  # Header field num we are looking for
    prev_state = 0  # Byte position inside header field
    prev_buffer = ""  # Aux var for packet processing

    # If program was called as 'active', then we need to make the first move and send a packet
    if active:
        prev_buffer = input_fh.read(MTU)

        if not prev_buffer:
            logging.warning("No contents found, check input file.")
            prev_buffer = ""

        # If the contents read are less in length then MTU, we won't bother reading the input file again
        send_no_more = True if len(prev_buffer) < MTU else False
        last_sent["data"] = prev_buffer
        last_sent["flags"] = 0x40 if send_no_more else 0x00
        last_sent["id"] = 0
        last_sent["length"] = len(prev_buffer)
        last_sent["checksum"], header = pack(last_sent)
        last_sent["packet"] = header + last_sent["data"]

        # Try to send the packet
        while True:
            # sock.settimeout(TIMEOUT)
            try:
                sock.send(last_sent["packet"])
                # sock.settimeout(None)
                logging.info("[SEND]: [Checksum: {}][Length: {}][ID: {}][Flags: {}]".format(last_sent["checksum"],
                                                                                            last_sent["length"],
                                                                                            last_sent["id"],
                                                                                            last_sent["flags"]))
                break
            except socket.timeout:
                pass

        prev_buffer = ""

    # Common behavior for both active and passive calls
    while True:
        while prev_header_field < 7:
            # sock.settimeout(TIMEOUT)
            try:
                recv_byte = sock.recv(1)
                # sock.settimeout(None)

                if not recv_byte:
                    raise socket.error

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
                        prev_buffer = ""

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
                        recv_no_more = True if recv_flags & 0x40 else False

                        # Checks if the protected bits are really protected
                        if recv_flags & 0x3f:
                            raise ValueError
                        if recv_length == 0:
                            break
                    prev_header_field += 1

                # Here we collect the data field (if any)
                elif prev_header_field == 6 and recv_length > 0:
                    if prev_state < recv_length:
                        prev_buffer += recv_byte
                        prev_state += 1
                    if prev_state == recv_length:
                        prev_header_field += 1
                        prev_state = 0
                        break
            except socket.timeout:
                recv_attempts += 1
                if recv_attempts == MAX_ATTEMPTS:
                    raise socket.timeout
            except ValueError:  # flags protected bits violation
                logging.error("Invalid packet flags! First 5 bits are protected.")

                # Drop the packet and restart process
                prev_header_field = 0
                prev_state = 0
                prev_buffer = ""

        logging.info("[RECV]: [Checksum: {}][Length: {}][ID: {}][Flags: {}]".format(recv_checksum, recv_length, recv_id, recv_flags))

        # Now we validate the checksum before processing the packet
        valid_checksum, packet = pack({"packet": None,
                                       "checksum": None,
                                       "length": recv_length,
                                       "id": recv_id,
                                       "flags": recv_flags,
                                       "data": prev_buffer})
        valid_checksum = valid_checksum == recv_checksum
        if valid_checksum:

            # Wrong ACK format
            if recv_flags & 0x80 and recv_length != 0:
                logging.error("ACK flags 0x80 present but length is not equal to zero.")

                # Drop the packet and restart process
                prev_buffer = ""
                prev_header_field = 0
                prev_state = 0

            # Correct ACK format
            elif recv_length == 0:

                # First ACK for last packet
                if recv_id == last_sent["id"] and recv_checksum == last_sent["checksum"]:
                    try:
                        prev_buffer = input_fh.read(MTU)
                        if not prev_buffer:
                            raise IOError
                    except IOError:
                        logging.warning("Input file is over. Will send an empty packet.")

                        # Restart process
                        prev_buffer = ""
                        prev_header_field = 0
                        prev_state = 0

                    # If the contents read are less in length then MTU, we won't bother reading the input file again
                    send_no_more = True if len(prev_buffer) < MTU else False
                    last_sent["data"] = prev_buffer
                    last_sent["flags"] = 0x80
                    last_sent["id"] ^= recv_id
                    last_sent["length"] = len(last_sent["data"])
                    last_sent["checksum"], header = pack(last_sent)
                    last_sent["packet"] = header + last_sent["data"]

                    # Try to send the packet
                    while True:
                        # sock.settimeout(TIMEOUT)
                        try:
                            sock.send(last_sent["packet"])
                            # sock.settimeout(None)
                            logging.info("[ACK ]: [Checksum: {}][Length: {}][ID: {}][Flags: {}]".format(last_sent["checksum"],
                                                                                                        last_sent["length"],
                                                                                                        last_sent["id"],
                                                                                                        last_sent["flags"]))
                            break
                        except socket.timeout:
                            pass

                    # At the end Keeps track of last received packet
                    last_recv = {"packet": packet, "checksum": recv_checksum, "length": recv_length, "id": recv_id, "data": prev_buffer}

                    # Restart process
                    prev_buffer = ""
                    prev_header_field = 0
                    prev_state = 0

                # Repeated ACK - Maybe peer didn't received confirmation
                elif recv_id == last_recv["id"] and recv_checksum == last_recv["checksum"]:
                    logging.warning("An error probably ocurred, I've received this ACK yet. Retransmitting...")

                    # Try to send the packet
                    while True:
                        # sock.settimeout(TIMEOUT)
                        try:
                            sock.send(last_sent["packet"])
                            # sock.settimeout(None)
                            logging.info("[RETR]: [Checksum: {}][Length: {}][ID: {}][Flags: {}]".format(last_sent["checksum"],
                                                                                                        last_sent["length"],
                                                                                                        last_sent["id"],
                                                                                                        last_sent["flags"]))
                            break
                        except socket.timeout:
                            pass

                    # Restart process
                    prev_buffer = ""
                    prev_header_field = 0
                    prev_state = 0

            # Just some data, lets send an ACK
            else:

                # Here we keep track of last received packet
                last_sent["data"] = ""
                last_sent["flags"] = 0x80
                last_sent["id"] = recv_id
                last_sent["length"] = 0
                last_sent["checksum"], header = pack(last_sent)
                last_sent["packet"] = header

                # Try to send the packet
                while True:
                    # sock.settimeout(TIMEOUT)
                    try:
                        sock.send(last_sent["packet"])
                        # sock.settimeout(None)
                        logging.info("[ACK ]: [Checksum: {}][Length: {}][ID: {}][Flags: {}]".format(last_sent["checksum"],
                                                                                                    last_sent["length"],
                                                                                                    last_sent["id"],
                                                                                                    last_sent["flags"]))
                        break
                    except socket.timeout:
                        pass

                # Restart process
                prev_buffer = ""
                prev_header_field = 0
                prev_state = 0

        else:
            logging.error("Wrong checksum field value! Dropping the packet.")
            prev_header_field = 0
            prev_state = 0
            prev_buffer = ""

        end_transmission = send_no_more and recv_no_more
        if not end_transmission:
            break

    logging.info("End of transmission!")
