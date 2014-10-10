yieldfromHttpLib
==============

Asyncio conversion of http.client)


The classes are named the same as in http.client.

class http.client.HTTPConnection(host, port=None, [timeout, ]source_address=None)

    conn = HTTPConnection('localhost', 8000)
    
    r = yield from conn.request('GET', '/pagename')
    resp = yield from conn.getresponse()
    
    yield from conn.connect()
    conn.putrequest(..)
    conn.putheader('X-Whatever', 'yesno')
    yield from conn.endheaders('message body')
    yield from conn.send('more body')
    
    resp = yield from conn.getresponse()
    # returns an HTTPResponse object
    
    

class http.client.HTTPSConnection(host, port=None, [timeout, ]source_address=None, context=None)

    conn = HTTPSConnection('localhost', 8000, context=context)
    # same as above


class http.client.HTTPResponse(sock, debuglevel=0, method=None, url=None)

Generally, you wont need to call the constructor directly, but if you do, you need to call the .init() method with yield from.

    resp = HTTPResponse(sock=sock)
    yield from resp.init()
    
Establishing the connection to the socket involves some input/output latency, so the yield from is required, and having the constructor itself be a coroutine would be sketchy.

    d = yield from resp.read()
    # or
    b = bytearray(10)
    d = yield from resp.readinto(b)


The fileno() method is a no-op.  The resp.fp attribute is an asyncio.StreamReader, with .read(), .readlines(), and .readexactly() methods, all coroutines.  The other attributes and methods work as per the regular HttpLib/http.client module.

