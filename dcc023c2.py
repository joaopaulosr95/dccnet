#!/usr/bin/env python
# coding=utf-8

"""
Joao Paulo Sacchetto Ribeiro Bastos
2013073440

Trabalho pratico 1
01-05-2017
"""

import sys
import errno
import time

from util import *


"""
| ===================================================================
| Main program
| ===================================================================
| Here we run a full-duplex DCCNET demo to transmit and receive data
"""

if __name__ == "__main__":

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
            passive_host = socket.gethostbyname(socket.getfqdn())
            passive_port = int(sys.argv[2])
            inputPath = sys.argv[3]
            outputPath = sys.argv[4]

        # Option not recornized
        else:
            IndexError
    except IndexError:
        helper()

    if passive_port not in range(51000, 55001):
        exit("Need a port between 51000 and 55000")

    # Initialize our filehandlers
    try:
        input_fh = open(inputPath, "rb")
        output_fh = open(outputPath, "wb")
    except IOError as e:
        logging.error("IOError({}): {}".format(e.errno, e.strerror))
        exit(1)

    # Here we create our socket
    dcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    """
    Lets (finally) start playing. First the program will open input and output files. 
    Based on behavior flag provided by user we now define if this program is gonna 
    make the first move or not.
    """
    attempts = 0

    if behavior == "active":
        dcc_sock.connect((passive_host, passive_port))
        logging.info("Connected to host {}:{}".format(passive_host, passive_port))

        dccnet_service(dcc_sock, input_fh, output_fh, True)

        logging.info("Closing connection with server {}:{}".format(passive_host, passive_port))
    else:

        # Tells OS that sock is now hearing at host:port
        dcc_sock.bind((passive_host, passive_port))
        logging.info("Socket binded at {}:{}".format(passive_host, passive_port))

        # Tells how many connections our server will handle at once
        dcc_sock.listen(MAX_CONN)

        while True:
            logging.info("Waiting for connections (max. {})".format(MAX_CONN))

            # Lets connect to our first client
            try:
                client_sock, client_addr = dcc_sock.accept()
                dcc_sock.settimeout(None)
                logging.info("Connection established with {}:{}. Waiting for message...".format(
                    client_addr[0], client_addr[1]))

                dccnet_service(client_sock, input_fh, output_fh)
            except socket.error as e:
                logging.error("Incomplete transmission!")
            finally:
                logging.info("Closing connection with client {}:{}".format(client_addr[0], client_addr[1]))
                client_sock.close()

    logging.info("Closing socket at {}:{}".format(passive_host, passive_port))
    dcc_sock.close()
    input_fh.close()
    output_fh.close()  # End of program
