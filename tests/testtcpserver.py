#!/usr/bin/env python
#
#  python-unittest-skeleton helper which allows for creating TCP
#  servers that misbehave in certain ways, for testing code.
#
#===============
#  This is based on a skeleton test file, more information at:
#
#     https://github.com/linsomniac/python-unittest-skeleton

import sys
import threading
import socket
import time
PY3 = sys.version > '3'


class TestTCPServer:
    '''A simple socket server so that specific error conditions can be tested.
    This must be subclassed and implment the "server()" method.

    The server() method would be implemented to do :py:func:`socket.send` and
    :py:func:`socket.recv` calls to communicate with the client process.
    '''

    GROUP = 'fakeTestTCPServer'

    STOPPED = False

    def _perConn(self, count):
        if not self.STOPPED:
            try:
                connection, addr = self.s.accept()
            except OSError as e:
                return
            except socket.timeout as e:
                return
        if not self.STOPPED:
            self.server(self.s, connection, count)
            count += 1

    def __init__(self, host='127.0.0.1', port=2222):

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        def _setup(self, evt):

            TestTCPServer.STOPPED = False

            self.s.settimeout(5)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind((host, port))
            self.s.listen(1)
            self.port = self.s.getsockname()[1]

            count = 0
            evt.set()
            while not self.STOPPED:
                self._perConn(count)
            self.s.close()

        while [t for t in threading.enumerate() if t.name == self.GROUP]:
            pass
        evt = threading.Event()
        thd = threading.Thread(name=self.GROUP, target=lambda: _setup(self, evt))
        thd.start()
        evt.wait()
        time.sleep(0.1)

    def server(self, sock, conn, ct):
        raise NotImplementedError('implement .server method')

    def stop(self):
        self.STOPPED = True
        self.s.close()



RECEIVE = None          # instruct the server to read data


class CommandServer(TestTCPServer):
    '''A convenience class that allows you to specify a set of TCP
    interactions that will be performed, providing a generic "server()"
    method for FakeTCPServer().

    For example, if you want to test what happens when your code sends some
    data, receives a "STORED" response, sends some more data and then the
    connection is closed:

    >>> fake_server = CommandServer(
    >>>     [RECEIVE, 'STORED\r\n', RECEIVE])
    >>> sc = memcached2.ServerConnection('memcached://127.0.0.1:{0}/'
    >>>         .format(fake_server.port))
    '''

    def __init__(self, commands, host='127.0.0.1', port=2222):
        self.commands = commands
        TestTCPServer.__init__(self, host, port)

    def server(self, sock, conn, count):
        quant = 0
        for command in self.commands:
            if command == RECEIVE:
                conn.recv(1000)
            else:
                if type(command) == type(b''):
                    conn.send(command)
                    quant += len(command)
                else:
                    if PY3:
                        conn.send(bytes(command, 'ascii'))
                        quant += len(command)
                    else:
                        conn.send(bytes(command))
                        quant += len(command)
        print('closing socket connection %s after %s bytes' % (conn.getpeername()[1], quant))
        conn.close()



class OneShotServer(CommandServer):

    def __init__(self, commands, host='127.0.0.1', port=2222):
        self.commands = commands #[RECEIVE, command]
        TestTCPServer.__init__(self, host, port)

    def _perConn(self, count):
        try:
            connection, addr = self.s.accept()
        except socket.timeout as e:
            return
        if not self.STOPPED:
            self.server(self.s, connection, count)
            count += 1
        self.stop()

