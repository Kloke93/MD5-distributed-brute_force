"""
Author: Tomas Dal Farra
Date:
Description: Brute force crack MD5 distributed computation administrator
"""
import sys
import socket
import select
import logging
from time import time


log_file = "md5server.log"      # file to save the log
log_level = logging.DEBUG       # set the minimum logger level
log_format = "%(asctime)s - %(levelname)s - %(message)s"    # logging format
logging.basicConfig(filename=log_file, level=log_level, format=log_format)


class Client:
    """
    Client information that server needs
    """
    max_time_interval = 15      # one minute and a half is the max interval between last connection and current time

    def __init__(self, address):
        """
        Initializes client information class
        :param address: contains address of client
        """
        self.address = address
        self.blocks = []                # blocks that client is working with
        self.last_time = time()

    def add_block(self, block: str):
        """
        Adds block to 'blocks' list
        :param block: block according to protocol
        """
        self.blocks.append(block)

    def is_alive(self) -> bool:
        """
        Checks how much time passed since the last time it communicated
        :return: returns if
        """
        return (time() - self.last_time) <= Client.max_time_interval


class AdminCracker:
    """
    Server to distribute work between clients giving them a range of numbers to work with
    """
    ip = "0.0.0.0"
    port = 16180
    listen_size = 8
    max_buffer = 64
    working_domain = (0, (10**10)-1)            # later padding strings to work just with 10 digits
    block_size = (10 ** 5)                   # how long will be each block
    original_len = 10                        # we suppose that length of the original string is 10

    def __init__(self, md5_hash: str):
        """
        Initialises server
        :param md5_hash: encoded string in hexadecimal format to crack
        """
        self.md5_hash = md5_hash
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setblocking(False)
        self.blocks = self.working_block(AdminCracker.block_size)       # blocks to work with
        self.client_dict = {}
        self.open_sockets = [self.server_socket]
        self.messages = []                                              # messages to send list (ip, data)
        self.found = False
        self.recovered_blocks = []

    @staticmethod
    def working_block(block_size: int):
        """
        generator that returns the necessary working block
        :param block_size: difference between where the block starts and finishes
        :return: next working block
        """
        now = 0
        post = block_size
        while post < AdminCracker.working_domain[1]:
            yield f"BLK {str(now).zfill(AdminCracker.original_len)} to {str(post).zfill(AdminCracker.original_len)}"
            now = post
            post += block_size
        yield f"BLK {str(now).zfill(AdminCracker.original_len)} to {str(AdminCracker.working_domain[1])}"
        logging.debug('last working block')

    @staticmethod
    def validate_data(data: str) -> bool:
        """
        Validates input from server according to protocol
        :param data: data to check its validity
        """
        if (data[:3] == "ASK") and (data[4:].isdigit()):
            return True
        elif (data[:3] == "SOL") and len(data[4:]) == AdminCracker.original_len:
            return True
        elif data == "":
            return True
        return False

    def handle_recovered(self, n: int, c: Client) -> str:
        """
        Sends to client some recovered blocks. If there aren't enough blocks we will send less
        :param n: how many blocks does the client need
        :param c: new client to handle blocks
        :return: returns message with blocks to send
        """
        count = len(self.recovered_blocks)
        if count > n:
            for _ in range(n):
                block = self.recovered_blocks[0]
                c.add_block(block)
                self.recovered_blocks.pop(0)
        else:
            for i in range(count):
                block = self.recovered_blocks[0]
                c.add_block(block)
                self.recovered_blocks.pop(0)
        start = c.blocks[0][:-10]
        end = c.blocks[-1][-10:]
        msg = start + end
        return msg

    def handle_communication(self, skt, data):
        """
        Handles communication with server
        :param skt: socket of the client that send the message
        :param data: data to handle
        """
        if data[:3] == "ASK":
            client_count = int(data[4:])     # according to client number of cpus a different size block will be sent
            client = self.client_dict[skt]
            client.blocks.clear()
            if not self.recovered_blocks:
                for _ in range(client_count):
                    block = next(self.blocks)
                    client.add_block(block)
                start = client.blocks[0][:-10]
                end = client.blocks[-1][-10:]
                msg = start + end
            else:
                msg = self.handle_recovered(client_count, client)
            self.messages.append((skt, msg))
        elif data[:3] == "SOL":
            print(data[4:])
            for i in range(len(self.open_sockets)-1):
                self.messages.append((self.open_sockets[1+i], "GOT"))
            self.found = True
            logging.info(f'Solution: {data[4:]}')
        elif data == "":                # empty message indicates disconnection
            self.open_sockets.remove(skt)
            c = self.client_dict[skt]
            logging.warning(f"{c.address} disconnected and left some blocks")
            self.recovered_blocks += c.blocks
            self.client_dict.pop(skt)
            skt.close()

    def run_server(self):
        """
        Runs server to administrate the distributed system
        """
        try:
            self.server_socket.bind((AdminCracker.ip, AdminCracker.port))
            self.server_socket.listen(AdminCracker.listen_size)
            while not self.found:
                rlist, wlist, xlist = select.select(self.open_sockets,
                                                    self.open_sockets[1:], self.open_sockets[1:])
                # exceptions
                for s in xlist:
                    logging.error(f"There is an exception in socket: {s}")
                    self.open_sockets.remove(s)
                # to read
                for s in rlist:
                    if s is self.server_socket:
                        client_socket, client_address = s.accept()
                        logging.debug(f"{client_address} is now connected")
                        new_client = Client(client_address)
                        self.client_dict[client_socket] = new_client
                        self.open_sockets.append(client_socket)
                        self.messages.append((client_socket, f"AIM {self.md5_hash}"))
                    else:
                        data = s.recv(AdminCracker.max_buffer).decode()
                        self.client_dict[s].last_time = time()
                        if len(data.split('*')) > 1:
                            for msg in data.split('*')[:-1]:
                                if self.validate_data(msg):
                                    self.handle_communication(s, msg)
                        else:
                            if self.validate_data(data):
                                self.handle_communication(s, data)
                # check if alive:
                for s in self.open_sockets[1:]:
                    c = self.client_dict[s]
                    if not c.is_alive():
                        self.recovered_blocks += c.blocks
                        logging.warning(f"{c.address} disconnected and left some blocks")
                        self.client_dict.pop(s)
                        self.open_sockets.remove(s)
                # to write
                for msg in self.messages:
                    s, data = msg
                    if s in wlist:
                        s.send((data + '*').encode())
                        self.messages.remove(msg)
        except socket.error as err:
            logging.critical(f'there was an error in line {sys.exc_info()[2].tb_lineno}: {err}')
        finally:
            for skt in self.open_sockets:
                skt.close()


def main():
    """
    run the program
    """
    start = time()
    s = AdminCracker(input('insert an MD5 string: '))
    s.run_server()
    print(time() - start)


if __name__ == "__main__":
    soc = AdminCracker('world-cup')   # not md5
    assert soc.validate_data("ASK 12")
    assert soc.validate_data("SOL ARGENTINAA")
    assert soc.validate_data("")
    assert not soc.validate_data("Champion")
    assert next(soc.blocks) == "BLK 0000000000 to 0000100000"
    main()
