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
MAX_ATTEMPTS = 10
MTU = 2 ** 10 - 1  # max bytes size for packet
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
        # sock.settimeout(TIMEOUT)
        try:
            ack_first_byte = sock.recv(1)
            # sock.settimeout(None)
            if ack_first_byte:
                break
        except socket.timeout:
            time.sleep(TIMEOUT)
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

def dccnet_service(sock, input_fh, output_fh, active=False):
    t1 = {
        "thread_id": 0,
        "recv_no_more": False,
        "send_no_more": False,
        "last_sent": {
            "checksum": None,
            "length": None,
            "id": None,
            "flags": None,
            "data": None,
            "packet": None
        },
        "last_recv": {
            "checksum": None,
            "length": None,
            "id": None,
            "flags": None,
            "data": None,
            "packet": None
        },
        "can_finish": False
    }
    t2 = {
        "thread_id": 1,
        "recv_no_more": False,
        "send_no_more": False,
        "last_sent": {
            "checksum": None,
            "length": None,
            "id": None,
            "flags": None,
            "data": None,
            "packet": None
        },
        "last_recv": {
            "checksum": None,
            "length": None,
            "id": None,
            "flags": None,
            "data": None,
            "packet": None
        },
        "can_finish": False
    }
    thread_pool = [t1, t2]

    # As soon as we call dccnet_service we will send a packet to the other side
    idx = 0 if active else 1
    target_thread = thread_pool[idx]

    try:
        prev_buffer = input_fh.read(MTU)
        if not prev_buffer:
            raise IOError
    except IOError:
        logging.warning(
            "[T{}] No more data to read from input file. Will send an empty packet.".format(
                thread_pool[idx]["thread_id"]))
        prev_buffer = ""

    # If the contents read are less in length then MTU, we won't bother reading the input file again
    target_thread["send_no_more"] = True if len(prev_buffer) < MTU else False

    # Here we keep track of last sent packet
    target_thread["last_sent"] = {
        "length": len(prev_buffer),
        "id": target_thread["thread_id"],
        "flags": 0x40 if target_thread["send_no_more"] else 0x00,
        "data": prev_buffer
    }
    target_thread["last_sent"]["checksum"], header = pack(target_thread["last_sent"])
    target_thread["last_sent"]["packet"] = header + target_thread["last_sent"]["data"]
    prev_buffer = ""

    try:
        ack_first_byte = interact(sock, target_thread["last_sent"]["packet"])
    except socket.error:
        raise socket.error

    logging.info("[T{}][SEND][DATA][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
        target_thread["thread_id"], target_thread["last_sent"]["checksum"], target_thread["last_sent"]["length"],
        target_thread["last_sent"]["id"], target_thread["last_sent"]["flags"]))

    target_thread["last_recv"]["id"] = (target_thread["thread_id"] + 1) % 2
    thread_pool[(idx + 1) % 2]["last_recv"]["id"] = target_thread["thread_id"]

    while True:

        # Try to fetch some new data if threads are still able to receive it
        # sock.settimeout(TIMEOUT)
        try:
            recv_packet = watcher(sock, output_fh, ack_first_byte)
            ack_first_byte = None
        except socket.error:
            raise socket.error
        # sock.settimeout(None)

        # Now we validate the checksum before processing the packet
        recalc_checksum, decoded_packet = pack(recv_packet)
        valid_checksum = recalc_checksum == recv_packet["checksum"]
        if valid_checksum:

            """
            Mux for choosing thread whom the packet is addressed for
            | '-c' thread |  do  | subject | '-s' thread |
            |-------------|------|---------|-------------|
            |      T0     | send |  data   |     T1      |
            |      T1     | recv |  data   |     T0      |
            |      T0     | recv |  ack    |     T1      |
            |      T1     | send |  ack    |     T0      |
            """
            target_thread = thread_pool[recv_packet["id"]]

            # Wrong ACK format
            if recv_packet["flags"] & 0x80 and recv_packet["length"] != 0:
                logging.error(
                    "[T{}][RECV][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]: Wrong format".format(
                        target_thread["thread_id"], recv_packet["checksum"], recv_packet["length"],
                        recv_packet["id"], recv_packet["flags"]))

            # Correct ACK format
            elif recv_packet["length"] == 0:

                # First ACK for last packet - Collect new data and send
                if recv_packet["id"] == target_thread["last_sent"]["id"] \
                        and not recv_packet["id"] == target_thread["last_recv"]["id"]:
                    logging.info(
                        "[T{}][RECV][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                            target_thread["thread_id"], recv_packet["checksum"], recv_packet["length"],
                            recv_packet["id"], recv_packet["flags"]))

                    # If I've received my ACK then I can (probably) finish
                    target_thread["can_finish"] = True

                    if not target_thread["send_no_more"]:
                        try:
                            prev_buffer = input_fh.read(MTU)
                            if not prev_buffer:
                                raise IOError
                        except IOError:
                            logging.warning(
                                "[T{}] No more data to read from input file. Will send an empty packet.".format(
                                    target_thread["thread_id"]))
                            prev_buffer = ""

                        # If the contents read are less in length then MTU, we won't read the input file again
                        target_thread["send_no_more"] = True if len(prev_buffer) < MTU else False

                        # Here we keep track of last sent packet
                        target_thread["last_sent"] = {
                            "length": len(prev_buffer),
                            "id": (target_thread["last_sent"]["id"] + 1) % 2,
                            "flags": 0x40 if target_thread["send_no_more"] else 0x00,
                            "data": prev_buffer
                        }
                        target_thread["last_sent"]["checksum"], header = pack(target_thread["last_sent"])
                        target_thread["last_sent"]["packet"] = header + target_thread["last_sent"]["data"]
                        prev_buffer = ""

                        try:
                            ack_first_byte = interact(sock, target_thread["last_sent"]["packet"])
                        except socket.error:
                            raise socket.error

                        logging.info(
                            "[T{}][SEND][DATA][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                                target_thread["thread_id"], target_thread["last_sent"]["checksum"],
                                target_thread["last_sent"]["length"], target_thread["last_sent"]["id"],
                                target_thread["last_sent"]["flags"]))

                        target_thread["can_finish"] = False

                # Repeated ACK
                elif recv_packet["id"] == target_thread["last_recv"]["id"] \
                        and recv_packet["checksum"] == target_thread["last_recv"]["checksum"]:
                    logging.info(
                        "[T{}][RECV][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                            target_thread["thread_id"], recv_packet["checksum"], recv_packet["length"],
                            recv_packet["id"], recv_packet["flags"]))
                    try:
                        ack_first_byte = interact(sock, target_thread["last_sent"]["packet"])
                    except socket.error:
                        raise socket.error
                    logging.info("[RETR][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                        target_thread["last_sent"]["checksum"], target_thread["last_sent"]["length"],
                        target_thread["last_sent"]["id"], target_thread["last_sent"]["flags"]))

                # What the f**k is this ACK?
                else:
                    logging.error(
                        "[T{}] I'm dropping this packet right now because I was not waiting for it".format(
                            target_thread["thread_id"]))

            # Its just some data, last send an ACK
            else:

                # Here we keep track of last received packet
                target_thread["last_recv"] = recv_packet
                target_thread["last_recv"]["packet"] = pack(target_thread["last_recv"])[1] + \
                                                       target_thread["last_recv"]["data"]
                target_thread["recv_no_more"] = True if not target_thread["recv_no_more"] \
                                                        and recv_packet["flags"] & 0x40 else False

                logging.info("[T{}][RECV][DATA][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                    target_thread["thread_id"], recv_packet["checksum"], recv_packet["length"], recv_packet["id"],
                    recv_packet["flags"]))

                # Here we keep track of last sent packet
                target_thread["last_sent"] = {
                    "length": 0,
                    "id": target_thread["last_recv"]["id"],
                    "flags": 0x80,
                    "data": ""
                }
                target_thread["last_sent"]["checksum"], header = pack(target_thread["last_sent"])
                target_thread["last_sent"]["packet"] = header

                try:
                    ack_first_byte = interact(sock, target_thread["last_sent"]["packet"])
                except socket.error:
                    raise socket.error
                logging.info("[T{}][SEND][ACK ][Checksum: {:5d}][Length: {:5d}][ID: {:1d}][Flags: {:3d}]".format(
                    target_thread["thread_id"], target_thread["last_sent"]["checksum"],
                    target_thread["last_sent"]["length"], target_thread["last_sent"]["id"],
                    target_thread["last_sent"]["flags"]))

                # If I've sent ACK then I (probably) can finish
                target_thread["can_finish"] = True

        else:
            logging.error(
                "[T{}] Wrong checksum field value! Dropping the packet.".format(target_thread["thread_id"]))
        prev_buffer = ""

        # If our threads have nothing more to do we can end transmission
        if thread_pool[0]["can_finish"] and thread_pool[1]["can_finish"]:
            # logging.debug("Both threads have nothing more to do")
            break

    logging.info("End of transmission!")

"""except socket.error:
    if e.errno != 10053:
        print("{}: {}".format(e.errno, e.strerror))
        raise socket.error
    else:
        pass"""
