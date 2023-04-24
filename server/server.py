#!/bin/env python

import socket
import select
import json
import logging
import sqlite3
import time
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import argparse

# users = {
#     'user1': {
#         "hash": '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e',
#         'pub_key': None,
#         'logined': False,
#         'socket': None,
#         'messages': [],
#     },
# }

# <- {"type": "register, "user", "username", "hash": "sha256_hash", "pub_key"}
# -> {"type": "register, "result", "OK|FAIL", "message", "details"}
# <- {"type": "auth", "user": "<username>", "hash": "sha256_hash"}
# -> {"type": "auth", "result": "OK|FAIL", "message": "details"}
# <- {"type": "contacts"}
# -> {"type": "contacts", "list": [{"name": "user1", "pub_key": "0x1234567890"}, {"name": "user2", "pub_key": "0xABCDEFGHIJ"}]}
# <- {"type": "req_key", "user": "user1"}
# -> {"type": "req_key", "user": "user1", "pub_key": "0x1234567890"}


class server(object):

    MSG_TYPE_REG = 'register'
    MSG_TYPE_AUTH = 'auth'
    MSG_TYPE_MSG = 'msg'
    MSG_TYPE_CONTACTS = 'contacts'
    MSG_TYPE_REQKEY = 'req_key'

    MSG_RESPONSE_OK = 'OK'
    MSG_RESPONSE_FAIL = 'FAIL'

    MSG_RESPONSE_CONTENT = '{{"type": "{type}", "result": "{result}", "message": "{message}"}}'

    def __init__(self, host='', port=9000):
        self.host = host
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(0)
        self.sock.setblocking(False)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.inputs = [self.sock]
        self.outputs = []

        self.sockets = {}
        self.users = {}

    def __del__(self):
        self.sock.close()

    def load_users(self, dbname):
        self.dbname = dbname

        conn = sqlite3.connect(dbname)
        cur = conn.cursor()

        try:
            for row in cur.execute('SELECT * FROM users;'):
                self.users[row[1]] = {'hash': row[4], 'pub_key': row[5], 'logined': False, 'socket': None, 'messages': []}
        except sqlite3.OperationalError:
            logging.info("Unable to find database in file. Create new one")
            cur.execute('CREATE TABLE IF NOT EXISTS  users(id INTEGER PRIMARY KEY, name VARCHAR, created INTEGER, last_login INTEGER, hash VARCHAR, pub_key VARCHAR);')
            conn.commit()
            conn.close()
        conn.close()

    def add_user(self, sock, user, password_hash, pub_key):
        if user in self.users:
            logging.warning(f"Username '{user}' is already exists")
            msg = encrypt(pub_key, self.MSG_RESPONSE_CONTENT.format(type=self.MSG_TYPE_REG, result=self.MSG_RESPONSE_FAIL, message='User is already exists').encode())
            sock.send(msg)

            if sock in self.inputs:
                self.inputs.remove(sock)
            sock.close()
            return False

        logging.info(f'Register user {user}')
        msg = self.MSG_RESPONSE_CONTENT.format(type=self.MSG_TYPE_REG, result=self.MSG_RESPONSE_OK, message='Registered')
        self.users[user] = {'hash': password_hash, 'pub_key': pub_key, 'logined': False, 'socket': None, 'messages': []}

        msg = encrypt(pub_key, msg.encode())
        sock.send(msg)

        conn = sqlite3.connect(self.dbname)
        cur = conn.cursor()
        cur.execute(f"INSERT INTO users VALUES(NULL, '{user}', {int(time.time())}, 0, '{password_hash}', '{pub_key}');")
        conn.commit()
        conn.close()
        return True

    def load_keys(self, key_path):
        self.key_path = key_path

        try:
            with open(key_path, 'r') as key_file:
                fc = key_file.read()
                j = json.loads(fc)
                self.public_key = j['public']
                self.private_key = j['private']
                logging.info('Server keys are loaded')
        except (FileNotFoundError, json.JSONDecodeError):
            logging.info('Unable to load keys. Generating keys...')
            privkey = generate_eth_key()
            self.private_key = privkey.to_hex()
            self.public_key = privkey.public_key.to_hex()

            with open(key_path, 'w') as key_file:
                key_file.write(f'{{"public": "{self.public_key}", "private": "{self.private_key}"}}')
            logging.info(f'Keys has been generated and stored to {key_path}')

    def new_connection(self, sock):
        new_conn, client_addr = sock.accept()
        new_conn.setblocking(False)
        new_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

        self.inputs.append(new_conn)
        self.sockets[new_conn] = None
        logging.info(f'New connection: {client_addr}')

    def authenticate(self, user, password_hash, sock):
        if not self.users.get(user):
            logging.warning(f"No such user {user}. Peer: {sock.getpeername()}")
            sock.send(self.MSG_RESPONSE_CONTENT.format(type=self.MSG_TYPE_AUTH, result=self.MSG_RESPONSE_FAIL, message=f'No such user {user}').encode())
            return False

        if self.users[user]['hash'] != password_hash:
            logging.warning(f"Login failed for user {user}. Peer: {sock.getpeername()}")
            sock.send(self.MSG_RESPONSE_CONTENT.format(type=self.MSG_TYPE_AUTH, result=self.MSG_RESPONSE_FAIL, message=f'Login failed for user {user}').encode())
            return False

        if self.users[user]['logined']:
            logging.warning(f'User {user} is already logined in. Peer {sock.getpeername()}')
            sock.send(self.MSG_RESPONSE_CONTENT.format(type=self.MSG_TYPE_AUTH, result=self.MSG_RESPONSE_FAIL, message=f'User {user} is already logined in').encode())
            return False

        self.users[user]['logined'] = True
        self.users[user]['socket'] = sock
        self.sockets[sock] = (self.users[user], user)
        self.send_message('server', user, {'type': self.MSG_TYPE_AUTH, 'result': self.MSG_RESPONSE_OK, 'message': 'Successfully authenticated'})

        conn = sqlite3.connect(self.dbname)
        cur = conn.cursor()
        cur.execute(f"UPDATE users SET last_login = {int(time.time())} WHERE id = (SELECT id FROM users WHERE name = '{user}');")
        conn.commit()
        conn.close()

        logging.info(f"Successfully authenticated: {user} from {sock.getpeername()}")

        return True

    def contacts(self, user):
        logging.debug(f'{user} requests contacts')
        users_list = {k: v['pub_key'] for k, v in self.users.items()}
        self.send_message('server', user, {'type': self.MSG_TYPE_CONTACTS, 'list': users_list})

    def req_key(self, requester, user):
        logging.debug(f'{requester} requests {user} key')
        if user not in self.users:
            logging.warning(f'Unable to send {user} key to {requester}. No such user')
            self.send_message('server', requester, {'type': self.MSG_TYPE_REQKEY, 'result': self.MSG_RESPONSE_FAIL, 'user': user, 'pub_key': ''})
            return

        self.send_message('server', requester, {'type': self.MSG_TYPE_REQKEY, 'result': self.MSG_RESPONSE_OK, 'user': user, 'pub_key': self.users[user]['pub_key']})

    def send_message(self, sender, recipient, message):
        if recipient not in self.users:
            logging.warning(f"Unable to send message to user {recipient}. User not found")
            return False

        logging.debug(f"Message from {sender} to {recipient}")

        message.update({'time': int(time.time()), 'sender': sender})
        message = json.dumps(message)
        message = encrypt(self.users[recipient]['pub_key'], message.encode())

        if sender == 'server':
            self.users[recipient]['messages'].insert(0, message)
        else:
            self.users[recipient]['messages'].append(message)

        if self.users[recipient]['socket'] and self.users[recipient]['socket'] not in self.outputs:
            self.outputs.append(self.users[recipient]['socket'])

        return True

    def serve_sock(self):
        while True:
            reads, send, excepts = select.select(self.inputs, self.outputs, self.inputs)

            for conn in reads:
                if conn == self.sock:  # Add new connection
                    self.new_connection(conn)

                else:  # The client wants to send the message
                    try:
                        data = conn.recv(1024 * 1024)
                    except ConnectionResetError:
                        data = None

                    if data:
                        try:
                            data = decrypt(self.private_key, data)
                            jdata = json.loads(data)
                        except (json.JSONDecodeError, ValueError):
                            logging.warning('Invalid message format')
                            continue
                        else:
                            # Handle authentication requests
                            if jdata.get('type') == self.MSG_TYPE_AUTH:
                                self.authenticate(jdata['user'], jdata['hash'], conn)
                                continue

                            # Handle messages
                            elif jdata.get('type') == self.MSG_TYPE_MSG and self.sockets[conn] and self.sockets[conn][0]['logined']:
                                self.send_message(self.sockets[conn][1], jdata.get('recipient'), jdata)
                                continue

                            # Handle register new user
                            elif jdata.get('type') == self.MSG_TYPE_REG:
                                self.add_user(conn, jdata.get('user'), jdata.get('hash'), jdata.get('pub_key'))
                                continue

                            # Handle contacts request
                            elif jdata.get('type') == self.MSG_TYPE_CONTACTS and self.sockets[conn] and self.sockets[conn][0]['logined']:
                                self.contacts(self.sockets[conn][1])
                                continue

                            # Handle key request
                            elif jdata.get('type') == self.MSG_TYPE_REQKEY and self.sockets[conn][0]['logined']:
                                self.req_key(self.sockets[conn][1], jdata.get('user'))
                                continue

                    else:  # The client has been disconnected
                        if conn in self.outputs:
                            self.outputs.remove(conn)
                        self.inputs.remove(conn)

                        if self.sockets[conn]:
                            self.sockets[conn][0]['logined'] = False
                            self.sockets[conn][0]['socket'] = None
                        del(self.sockets[conn])
                        conn.close()
                        logging.info('Client has been disconnected')

            # The server has messages to send
            for conn in send:
                for _ in range(len(self.sockets[conn][0]['messages'])):
                    conn.send(self.sockets[conn][0]['messages'][0])
                    self.sockets[conn][0]['messages'].remove(self.sockets[conn][0]['messages'][0])
                    time.sleep(0.01)
                self.outputs.remove(conn)

            for conn in excepts:
                logging.error('Select error occurred')
                self.inputs.remove(conn)
                if conn in self.outputs:
                    self.outputs.remove(conn)
                conn.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

    parser = argparse.ArgumentParser(description='DNS-proxy server')
    parser.add_argument('-k', dest='key', required=False, help='Server key file', default='server.key')
    parser.add_argument('-n', dest='host', required=False, help='Bind to host', default='localhost')
    parser.add_argument('-p', dest='port', type=int, required=False, help='Server port', default='9000')
    parser.add_argument('-b', dest='db', required=False, help='Database path', default='users.sqlite3')
    args = parser.parse_args()

    logging.info('Starting server...')
    srv = server(args.host, args.port)
    logging.info(f'Loading server keys from {args.key}...')
    srv.load_keys(args.key)
    logging.info(f'Loading users from {args.db}...')
    srv.load_users(args.db)
    logging.info('Listening to connections')
    srv.serve_sock()
