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


log_file = "md5server.log"          # file to save the log
log_level = logging.DEBUG           # set the minimum logger level
log_format = "%(asctime)s - %(levelname)s - %(message)s"   # logging format
logging.basicConfig(filename=log_file, level=log_level, format=log_format)


class Client:
    """
    Client information so server administrates special cases
    """
    max_time_interval = 90      # one minute and a half is the max interval between last connection and current time

    def __init__(self, address, soc):
        """
        Initializes client information class
        """
        self.address = address
        self.socket = soc
        self.blocks = []                # blocks that client is working with
        self.last_time = time()

    def add_block(self, block: int):
        """
        Adds block to 'blocks' list
        :param block: last number in the block
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
    block_size = 2 * (10 ** 5)                  # how long will be each block

    def __init__(self, md5_hash: str):
        """
        Initialises server
        :param md5_hash: encoded string in hexadecimal format to crack
        """
        self.md5_hash = md5_hash
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setblocking(False)
        self.blocks = self.working_block(AdminCracker.block_size)

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
            yield f"block from {str(now).zfill(10)} to {str(post).zfill(10)}"
            now = post
            post += block_size
        yield f"block from {str(now).zfill(10)} to {str(AdminCracker.working_domain[1])}"
        logging.debug('last working block')

    def run_server(self):
        """
        Runs server to administrate the distributed system
        """
        try:
            self.server_socket.bind((AdminCracker.ip, AdminCracker.port))
            self.server_socket.listen(AdminCracker.listen_size)
            open_sockets = [self.server_socket]

            while self.server_socket in open_sockets:
                rlist, wlist, xlist = select.select(open_sockets, open_sockets, open_sockets)
                # exceptions
                for s in xlist:
                    logging.error(f"There is an exception in socket: {s}")
                    open_sockets.remove(s)
                # to read
                for s in rlist:
                    if s is self.server_socket:
                        client_socket, client_address = s.accept()
                        logging.debug(f"{client_address} is now connected")
                        open_sockets.append(client_socket)
                    else:
                        data = s.recv(AdminCracker.max_buffer).decode()
                        if data == "":
                            open_sockets.remove(s)
                            s.close()
                        data_list = data.split()
                        if data[0] == "solution":
                            pass
                # to write
                for s in wlist:
                    pass

        except socket.error as err:
            logging.critical(f'there was an error in line {sys.exc_info()[2].tb_lineno}: {err}')
        finally:
            self.server_socket.close()


def main():
    """
    run the program
    """
    # s = AdminCracker(input('insert an MD5 string: '))
    # s.run_server()
    pass


if __name__ == "__main__":
    main()
