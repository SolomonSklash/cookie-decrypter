try:
    import sys
    import struct
except ImportError:
    print "Failed to load dependencies in F5 decrypt."


def decryptCookie(cookie):
    encoded_string = cookie

    (host, port, end) = encoded_string.split('.')

    (a, b, c, d) = [ord(i) for i in struct.pack("<I", int(host))]

    (e) = [ord(e) for e in struct.pack("<H", int(port))]
    port = "0x%02X%02X" % (e[0], e[1])

    result = "%s.%s.%s.%s:%s" % (a, b, c, d, int(port, 16))

    return result