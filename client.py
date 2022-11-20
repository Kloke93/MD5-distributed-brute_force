"""
Author: Tomas Dal Farra
Date:
Description:
"""
import socket
import sys
import threading
import hashlib
import logging
from sys import argv
import os


log_file = "md5client.log"      # file to save the log
log_level = logging.DEBUG       # set the minimum logger level
log_format = "%(asctime)s - %(levelname)s - %(message)s"    # logging format
logging.basicConfig(filename=log_file, level=log_level, format=log_format)


class Client:
    """
    Client to handle
    """
    server_port = 16180
    max_buffer = 128

    def __init__(self, ip="127.0.0.1"):
        """
        Creates client socket to receive working domains
        :param ip: Ip of the server to work with
        """
        # General
        self.server_address = (ip, Client.server_port)
        self.target = ""                                # target encoded string (given by server)
        self.original = ""                              # the original string found in computer (may not get this)
        self.found = False                              # if original is found (by server of by ourselves)
        self.got = False
        self.original_length = 10                       # we suppose that length of the original string is 10
        self.blocks = []                                # all blocks (start, end) to compute
        # Sockets
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         # creates socket instance
        self.client.settimeout(30)                                              # in case server fell
        # Threads
        self.threads = []  # list that contains all threads (one per logical core in this program)

    def compute(self, block: tuple):
        """
        Computes along the block
        :param block: tuple with starting int and an int endpoint
        """
        for i in range(block[0], block[1] + 1):
            if hashlib.md5(str(i).zfill(self.original_length).encode()).hexdigest() == self.target:
                self.original = str(i).zfill(self.original_length)
                logging.debug(f'original string found. {self.original}')
                break                               # original string found, no need to keep looping

    def thread_work(self):
        """
        Handles all client threads:
        Cleans thread list, creates new threads, puts them to work and compute all blocks we have.
        Then joins all threads and handles according to the result (original found or not)
        """
        for i in range(os.cpu_count()):
            thread = threading.Thread(target=self.compute, name=f"Thread-{i+1}", args=(self.blocks[i],))
            thread.start()
            self.threads.append(thread)
        for thread in self.threads:
            thread.join()
        self.blocks.clear()
        self.threads.clear()

    def validate_data(self, data: str) -> bool:
        """
        Validates input from server according to protocol
        :param data: data to check its validity
        """
        if data[:3] == "BLK" and len(data) == (8 + self.original_length * 2):
            return True
        elif (data[:3] == "AIM") and (len(data) == 36) and (not self.target):
            return True
        elif data[:3] == "GOT":
            return True
        elif data == "":
            return True
        return False

    def get_blocks(self, chunk):
        """
        From a BLK instruction separates all blocks from a chunk
        :param chunk: the entire block that has to be reparted
        """
        start = int(chunk[:10])
        end = int(chunk[14:])
        block_size = (end - start) // os.cpu_count()       # floor of the total block size and the cpu count
        for i in range(os.cpu_count() - 1):
            new = start, start + block_size - 1
            start += block_size
            self.blocks.append(new)
        self.blocks.append((start, end))

    def handle_communication(self, data):
        """
        Handles communication with server
        :param data: data to handle
        """
        instruc = data[:3]              # instruction according to protocol
        if instruc == "BLK":
            self.get_blocks(data[4:])
            self.thread_work()
            if self.original:
                self.client.send(f"SOL {self.original}*".encode())
            else:
                self.client.send(f"ASK {os.cpu_count()}*".encode())
        elif instruc == "AIM":
            self.target = data[4:]
        elif instruc == "GOT":
            self.found = True
        elif data == "":
            self.client.close()

    def run(self):
        """
        Runs client:
        1) connect to server
        2) Work according to the protocol
        """
        try:
            self.client.connect(self.server_address)
            self.client.send(f"ASK {os.cpu_count()}*".encode())
            while not self.found:
                msg = self.client.recv(Client.max_buffer).decode()
                if len(msg.split('*')) > 1:
                    for ms in msg.split('*')[:-1]:
                        if self.validate_data(ms):
                            self.handle_communication(ms)
                else:
                    logging.warning("message doesn't contain '*'")
                    if self.validate_data(msg):
                        self.handle_communication(msg)
        except socket.error as err:
            logging.critical(f'there was an error in line {sys.exc_info()[2].tb_lineno}: {err}')
        finally:
            self.client.close()


def main():
    if len(argv) > 1:
        client = Client(argv[1])
    else:
        client = Client()
    client.run()


if __name__ == "__main__":
    c = Client()
    assert c.validate_data('AIM 639fc2398fd45606ada087e30168287b')
    c.target = '639fc2398fd45606ada087e30168287b'
    assert not c.validate_data('AIM 639fc2398fd45606ada087e30168287b')
    c.get_blocks('0000000000 to 0002400000')
    c.thread_work()
    assert c.found
    assert c.validate_data("BLK 0000000000 to 0000100000")
    assert c.validate_data("GOT")
    assert c.validate_data("")
    main()
