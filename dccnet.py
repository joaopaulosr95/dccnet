#!/usr/bin/env python
# coding=utf-8

"""
Copyright (c) 2017 Joao Paulo Bastos <joaopaulosr95@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import socket

import logging

from dccnet import utils

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
| Main program
| ===================================================================
| Here we run a full-duplex DCCNET demo to transmit and receive data
"""

if __name__ == "__main__":
    logger = logging.getLogger(__name__)

    # Lets check if the CLI parameters are as expected
    try:
        # Client perspective
        if "-c" in sys.argv[1]:
            behavior = "active"
            passive_host = sys.argv[2].split(":")[0]
            passive_port = int(sys.argv[2].split(":")[1])
            inputPath = sys.argv[3]
            outputPath = sys.argv[4]

        # Server perspective
        elif "-s" in sys.argv[1]:
            behavior = "passive"
            passive_host = "150.164.6.45"  # socket.gethostbyname(socket.getfqdn())
            passive_port = int(sys.argv[2])
            inputPath = sys.argv[3]
            outputPath = sys.argv[4]
        else:
            raise IndexError
    except IndexError:
        utils.helper()

    if passive_port not in range(51000, 55001):
        exit("Need a port between 51000 and 55000")

    # Initialize our filehandlers
    try:
        input_fh = open(inputPath, "rb")
        output_fh = open(outputPath, "wb")
    except IOError as e:
        logging.error("IOError({}): {}".format(e.errno, e.strerror))
        exit(1)

    dcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Here we create our socket

    """ç
    Lets (finally) start playing. First the program will open input and output files.
    Based on behavior flag provided by user we now define if this program is gonna
    make the first move or not.
    """
    attempts = 0

    if behavior == "active":
        dcc_sock.connect((passive_host, passive_port))
        logging.info("Connected to host {}:{}".format(passive_host, passive_port))
        try:
            utils.dccnet_service(dcc_sock, input_fh, output_fh)
        except socket.error as e:
            logging.error("Incomplete transmission!")
        finally:
            logging.info("Closing connection with server {}:{}".format(passive_host, passive_port))
    else:
        dcc_sock.bind((passive_host, passive_port))  # Tells OS that sock is now hearing at host:port
        logging.info("Socket binded at {}:{}".format(passive_host, passive_port))
        dcc_sock.listen(utils.MAX_CONN)  # Tells how many connections our server will handle at once
        logging.info("Waiting for connections (max. {})".format(utils.MAX_CONN))
        try:
            client_sock, client_addr = dcc_sock.accept()
            logging.info("Connection established with {}:{}. Waiting for message...".format(
                client_addr[0], client_addr[1]))
            utils.dccnet_service(client_sock, input_fh, output_fh)
        except socket.error as e:
            logging.error("Incomplete transmission!")
        finally:
            logging.info("Closing connection with client {}:{}".format(client_addr[0], client_addr[1]))
            logging.info("Closing socket at {}:{}".format(passive_host, passive_port))
            client_sock.close()

    dcc_sock.close()
    input_fh.close()
    output_fh.close()

# End of program
