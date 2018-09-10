"""
Netscaler Cookie Decryptor - decrypts Netscaler load balancer persistence cookies
Copyright (C) 2012  Adam Maxwell - catalyst256@gmail.com 
Nick: @catalyst256
Blog: itgeekchronicles.co.uk

Thanks to:
Alejandro Nolla Blanco - alejandro.nolla@gmail.com - @z0mbiehunt3r - for the inspiration to write this and for adding the error correction.
Daniel Grootveld - danielg75@gmail.com - @shDaniell - for helping with the XOR method of decryption, adding the service port decryption and for making my regex more robust.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

@author: Adam Maxwell
@license: GPL v2
@date: 23-01-2012
@version: 0.3.1

"""
try:
    import sys
    import re
    import string
    from string import maketrans, ascii_letters
except ImportError:
    print "Failed to load dependencies in Netscaler decrypt."


def parseCookie(cookie):
    """Parse Citrix NetScaler cookie
    @param cookie: Citrix NetScaler cookie
    @return: Returns ServiceName, ServerIP and ServerPort
    """
    s = re.search(r'NSC_([a-zA-Z0-9\-\_\.]*)=[0-9a-f]{8}([0-9a-f]{8}).*([0-9a-f]{4})$',cookie)
    if s is not None:
        servicename = s.group(1)  # first group is name ([a-z\-]*)
        serverip = int(s.group(2), 16)
        serverport = int(s.group(3), 16)
    else:
        raise Exception('Could not parse cookie')
    return servicename, serverip, serverport


def decryptServiceName(servicename):
    """Decrypts the Caesar Subsitution Cipher Encryption used on the Netscaler Cookie Name
    @param cookie Citrix NetScaler cookie
    @type cookie: String
    @return: service name
    """

    alphaPlain = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    alphaShifted = 'zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY'
    try:
        result = ''
        for i in range(0, len(servicename)):
            if(not servicename[i].isdigit()):
                offset = alphaShifted.find(servicename[i])
                result += alphaPlain[(offset - 2) % 52]
            else:
                result += servicename[i]
    except:
        print 'Failed to convert servicename.'

    return result


def decryptServerIP(serverip):
    """Decrypts the XOR encryption used for the Netscaler Server IP
    @param cookie Citrix NetScaler cookie
    @type cookie: String
    @return: XORed server IP based on ipkey
    """
    try:
        ipkey = 0x03081e11
        decodedip = hex(serverip ^ ipkey)
        t = decodedip[2:10].zfill(8)
        realip = '.'.join(str(int(i, 16)) for i in([t[i:i+2] for i in range(0, len(t), 2)]))
        return realip
    except:
        print 'Failed in decryptServerIP.'


def decryptServerPort(serverport):
    """Decrypts the XOR encryption used on the Netscaler Server Port
    @param cookie Citrix NetScaler cookie
    @type cookie: String
    @return: XORed server port
    """
    try:
        portkey = 0x3630
        decodedport = serverport ^ portkey  # no need to convert to hex since an integer will do for port
        realport = str(decodedport)
        return realport
    except:
        print 'Failed in decryptServerPort.'


def decryptCookie(cookie):
    """Make entire decryption of Citrix NetScaler cookie
    @param cookie: Citrix NetScaler cookie
    @return: Returns RealName, RealIP and RealPort
    """
    try:
        servicename, serverip, serverport = parseCookie(cookie)
    except:
        print 'Failed to get parsed values from cookie.'
    try:
        realname = decryptServiceName(servicename)
    except:
        print 'Failed to get real name.'
    try:
        realip = decryptServerIP(serverip)
    except:
        print 'Failed to get real IP.'
    try:
        realport = decryptServerPort(serverport)
    except:
        print 'Failed to get server port.'

    return realname + ':' + realip + ':' + realport
