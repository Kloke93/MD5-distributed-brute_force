"""
Author: Tomas Dal Farra
Date:
Description: Brute force crack MD5 distributed computation administrator
"""
import sys
import socket
import select
import logging


log_file = "md5server.log"          # file to save the log
log_level = logging.DEBUG           # set the minimum logger level
log_format = "%(asctime)s - %(levelname)s - %(message)s"   # logging format
logging.basicConfig(filename=log_file, level=log_level, format=log_format)


class AdminCracker:
    """
    Server to distribute work between clients giving them a range of numbers to work with
    """
    ip = "0.0.0.0"
    port = 16180
    listen_size = 8
    max_buffer = 64

    def __init__(self, md5_hash: str):
        """
        Initialises server
        :param md5_hash: encoded string in hexadecimal format to crack
        """
        self.md5_hash = md5_hash
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setblocking(False)

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
