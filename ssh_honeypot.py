#!/usr/bin/env python

from datetime import datetime
from ipaddress import ip_address
from time import sleep
import argparse
import paramiko
import socket
import threading


class SSHServer(paramiko.ServerInterface):
    def __init__(self, server_address, server_port, server_key, logfile=None, csv_file=None):
        if not self._is_valid_ip(server_address):
            raise ValueError('[-] Invalid server IPv4 address provided.')
        if not self._is_valid_port(server_port):
            raise ValueError('[-] Invalid server port number provided.')
        if not self._is_valid_key(server_key):
            raise InvalidRSAKeyError
        self.server_address = server_address
        self.server_port = server_port
        self.server_key = paramiko.RSAKey.from_private_key_file(server_key)
        self.running = False
        self.logfile = logfile
        self.csv_file = csv_file
        self.log_lock = threading.Lock()
        if self.logfile:
            with open(self.logfile, 'w') as f:
                f.write('SSH Honeypot Event Log:\n\n')
        if self.csv_file:
            with open(self.csv_file, 'w') as f:
                f.write('Timestamp,Username,Password\n')


    def _is_valid_ip(self, address):
        try:
            ip_address(address)
            return True
        except:
            return False

    def _is_valid_port(self, port):
            return 1 <= port <= 65535

    def _is_valid_key(self, server_key):
        try:
            paramiko.RSAKey.from_private_key_file(server_key)
            return True
        except:
            return False

    def start_server(self):
        if not self.running:
            self.running = True
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self.sock.bind((self.server_address, self.server_port))
            except Exception as e:
                print(f'[-] Error when binding host address: {e}')
                self.stop_server()
                return
            self.sock.listen(50)
            self.log(f'[+] SSH server listening on {self.server_address}:{self.server_port}')
            try:
                while True:
                    client_sock, addr = self.sock.accept()
                    self.log(f'[+] Received connection from {addr[0]}:{addr[1]}.')
                    client_thread = threading.Thread(target=self.handle_client_conn, args = (client_sock,))
                    client_thread.start()
            except Exception as e:
                self.log(f'[-] Client socket error: {e}')
            except KeyboardInterrupt:
                self.log('[+] Received interrupt signal.')
            finally:
                self.stop_server()

    def stop_server(self):
        self.log('[+] Shutting down server...')
        self.sock.close()
        self.running = False

    def handle_client_conn(self, client_sock):
        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = 'SSH-2.0-OpenSSH_9.7'
            transport.add_server_key(self.server_key)
            transport.start_server(server=self)
            channel = transport.accept()
            if channel is None:
                raise Exception('Failed to open channel')
        except Exception as e:
            self.log(f'[-] Error handling client connection: {e}')
        finally:
            client_sock.close()

    def check_auth_password(self, username, password):
        if self.csv_file:
            with open(self.csv_file, 'a') as f:
                f.write(f'{datetime.now()},{username},{password}\n')
        print(f'{datetime.now()} - {username} : {password}')
        sleep(1.25)
        return paramiko.AUTH_FAILED

    def log(self, message):
        if self.logfile:
            with self.log_lock:
                with open(self.logfile, 'a') as f:
                    f.write(f'{datetime.now()} - {message}\n')
        print(message)

class InvalidRSAKeyError(Exception):
    def __init__(self):
        self.message = '[-] Invalid RSA key provided.'
        super().__init__(self.message)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='SSH Honeypot written using the Paramiko library to log access attempts and cleartext credentials.',
        epilog='"$ ssh-keygen -i <KEY_NAME> -t rsa" to generate key if you havent already\n',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('server_address', type=str, help='IPv4 address the server will listen on')
    parser.add_argument('server_port', type=int, default=2222, help='port the server will listen on')
    parser.add_argument('server_key', type=str, help='RSA SSH hostkey (/path/to/private.key)')
    parser.add_argument('-l', '--logfile', nargs='?', const=True, default=False, type=str, help='log events to file LOGFILE (default is ./honeypot.log)')
    parser.add_argument('-c', '--csv', nargs='?', const=True, default=False, type=str, help='log credentials to csv file FILENAME (default is creds.csv)')
    args = parser.parse_args()
    return args

def main():
    args = parse_arguments()
    if args.logfile == True:
        args.logfile = 'honeypot.log'
    if args.csv == True:
        args.csv = 'creds.csv'
    honeypot = SSHServer(args.server_address, args.server_port, args.server_key, args.logfile, args.csv)
    honeypot.start_server()

if __name__ == '__main__':
    main()
