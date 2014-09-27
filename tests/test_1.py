
import socket
import aioclient
import asyncio

import unittest
import testtcpserver as server
from testtcpserver import RECEIVE

TestCase = unittest.TestCase


CONNECT = ('127.0.0.1', 2222)


chunked_start = (
    'HTTP/1.1 200 OK\r\n'
    'Transfer-Encoding: chunked\r\n\r\n'
    'a\r\n'
    'hello worl\r\n'
    '3\r\n'
    'd! \r\n'
    '8\r\n'
    'and now \r\n'
    '22\r\n'
    'for something completely different\r\n'
)
chunked_expected = b'hello world! and now for something completely different'
chunk_extension = ";foo=bar"
last_chunk = "0\r\n"
last_chunk_extended = "0" + chunk_extension + "\r\n"
trailers = "X-Dummy: foo\r\nX-Dumm2: bar\r\n"
chunked_end = "\r\n"



def open_socket_conn(host='127.0.0.1', port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect((host, port))
    return sock


testLoop = asyncio.get_event_loop()


class BasicTest(TestCase):


    def test0_plain(self):


        def _temp():
            sock = open_socket_conn(*CONNECT)
            sock.sendall(b' ')

            resp = aioclient.HTTPResponse(sock, method="GET")
            yield from resp.init()
            yield from resp.begin()
            eof = resp.fp.at_eof()
            r1 = yield from resp.read()
            resp.close()
            #sock.close()

        #srvr = server.OneShotServer([RECEIVE, chunked_start + last_chunk + chunked_end], *CONNECT)
        srvr = server.OneShotServer([RECEIVE, 'HTTP/1.1 200 OK\r\n', 'asdlkfjasdl fasdlfj asdfj asdf asdf'], *CONNECT)
        #srvr = server.OneShotServer([RECEIVE, chunked_start], *CONNECT)
        testLoop.run_until_complete(_temp())


    def test1_chunked(self):


        def _temp():
            sock = open_socket_conn(*CONNECT)
            sock.sendall(b' ')

            resp = aioclient.HTTPResponse(sock, method="GET")
            yield from resp.init()
            yield from resp.begin()
            eof = resp.fp.at_eof()
            r1 = yield from resp.read()
            resp.close()
            #sock.close()

        srvr = server.OneShotServer([RECEIVE, chunked_start + last_chunk + chunked_end], *CONNECT)
        #srvr = server.OneShotServer([RECEIVE, 'HTTP/1.1 200 OK\r\n', 'asdlkfjasdl fasdlfj asdfj asdf asdf'], *CONNECT)
        testLoop.run_until_complete(_temp())
