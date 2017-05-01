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
| Here we go with a full-duplex DCCNET program to transmit and 
| receive data simultaneously
"""

if __name__ == "__main__":

    max_conn = 1  # max connections our program can handle

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
            raise IndexError
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
    Lets (finally) start playing. First the program will open input 
    and output files. Based on behavior flag provided by user we now
    define if this program is gonna make the first move or not.
    """
    if behavior == "active":
        dcc_sock.connect((passive_host, passive_port))
        logging.info("Connected to host {}:{}".format(passive_host, passive_port))

        # Through this we can watch network for packets. This is a mutual behavior from senders and reveiver
        watcher(dcc_sock, input_fh, output_fh, True)

        logging.info("Closing connection with server {}:{}".format(passive_host, passive_port))

    else:
        # Tells OS that sock is now hearing at host:port
        dcc_sock.bind((passive_host, passive_port))
        logging.info("Socket binded at {}:{}".format(passive_host, passive_port))

        # Tells how many connections our server will handle at once
        dcc_sock.listen(max_conn)
        logging.info("Waiting for connections (max. {})".format(max_conn))

        # Lets connect to our first client
        client_sock, addr = dcc_sock.accept()
        active_host, active_port = addr[0], addr[1]
        logging.info("Connection established with {}:{}. Waiting for message...".format(active_host, active_port))

        # Through this we can watch network for packets. This is a mutual behavior from senders and reveivers
        watcher(client_sock, input_fh, output_fh)
        logging.info("Closing connection with client {}:{}".format(active_host, active_port))

        client_sock.close()

    logging.info("Closing socket at {}:{}".format(passive_host, passive_port))
    dcc_sock.close()

    # End of program
    input_fh.close()
    output_fh.close()
