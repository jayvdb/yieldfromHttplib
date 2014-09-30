yieldfromHttpLib
==============

Asyncio conversion of HttpLib (in Python3, known as http.client)


The classes are named the same as in http.client.

class http.client.HTTPConnection(host, port=None, [timeout, ]source_address=None)

    conn = HTTPConnection('localhost', 8000)
    #
    r = yield from conn.request('GET', '/pagename')
    resp = yield from conn.getresponse()
    #
    yield from conn.connect()
    yield from conn.putrequest(..)
    conn.putheader('X-Whatever', 'yesno')
    yield from conn.endheaders('message body')
    yield from conn.send('more body')
    #
    resp = yield from conn.getresponse()
    
    

class http.client.HTTPSConnection(host, port=None, [timeout, ]source_address=None)

    conn = HTTPSConnection('localhost', 8000, context=context)
    # same as above


@asyncio.coroutine
class http.client.HTTPResponse(sock, debuglevel=0, method=None, url=None)

Generally, you wont need to call the constructor directly, but if you do, you need to call the .init() method with yield from.

    resp = HTTPResponse(sock=sock)
    yield from resp.init()
    
Establishing the connection to the socket involves some Input/Output latency, so the yield from is required, and having the constructor itself be a coroutine would be sketchy.

