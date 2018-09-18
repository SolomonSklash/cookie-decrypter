import zlib
import json
from base64 import b64decode, urlsafe_b64decode


def check_or_decode(s, encoding='utf-8', errors='strict'):
    if isinstance(s, str):
        s = s.decode(encoding, errors)
    return s


def check_or_encode(s, encoding='utf-8', errors='strict'):
    if isinstance(s, unicode):
        s = s.encode(encoding, errors)
    return s


def dangerous64_decode(s):
    s = check_or_encode(s, encoding='ascii', errors='ignore')
    b64padding = b'=' * (-len(s) % 4)
    s = '%s%s' % (s, b64padding)
    try:
        return urlsafe_b64decode(s)
    except:
        print 'Exception in dangerous64_decode'
        raise Exception('Not a valid base64-encoded string')


def decode(cookie):
    is_compressed = True if cookie.startswith('.') else False
    session_segment = dangerous64_decode(filter(None, cookie.split('.'))[0])
    if is_compressed:
        session_segment = zlib.decompress(session_segment)
    try:
        session_segment = json.loads(
            check_or_decode(session_segment, errors='ignore'))
        for key, val in session_segment.iteritems():
            try:
                session_segment[key] = b64decode(
                    session_segment[key].values()[0])
            except:
                pass
        return session_segment
    except Exception as e:
        print e
        return None
    print 'Returning ' + session_segment
    return session_segment
