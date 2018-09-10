"""
Name:           Cookie Decrypter
Version:        2.0.0
Date:           08/17/2018
Author:         bellma101 - bellma101@0xfeed.io - Penetration Tester with FIS Global
Gitlab:         https://github.com/bellma101/cookie-decrypter/
Description:    This extension detects the usage of Citrix Netscaler
persistence cookies and decrypts them. It requires Jython 2.7+.

The following Burp extensions were reviewed to help write this:
- ActiveScan++: https://github.com/albinowax/ActiveScanPlusPlus
- SQLiPy: https://github.com/PortSwigger/sqli-py
- Yara: https://github.com/PortSwigger/yara/
- http://blog.opensecurityresearch.com/2014/03/extending-burp.html
- https://blog.secureideas.com/2013/08/burp-extension-for-f5-cookie-detection.html

Special thanks to Adam Maxwell and his Netscaler-Cookie-Decryptor, upon which
the Netscaler decryption code of this extension is based.
 - https://github.com/catalyst256/Netscaler-Cookie-Decryptor
 And to James Jardine, for his post on F5 cookie decoding.
 - https://blog.secureideas.com/2013/02/decoding-f5-cookie.html
 And to Steve Coward for Cookie Crunch, for decoded Flask cookies.
 - https://github.com/stevecoward/cookie-crunch

Copyright (c) 2018 bellma101
"""

try:
    from burp import IBurpExtender, IScannerCheck, IScanIssue
    from java.lang import RuntimeException
    from java.io import PrintWriter
    from array import array
    import re
    import sys
    import string
    from string import maketrans, ascii_letters
    import zlib
    import json
    from base64 import b64decode, urlsafe_b64decode
    import nsccookiedecrypt
    import f5cookiedecrypt
    import flaskcookiedecrypt
except ImportError:
    print "Failed to load dependencies."

VERSION = '2.0.0'

# Inherit IBurpExtender as base class, which defines registerExtenderCallbacks
# Inherit IScannerCheck to register as custom scanner


class BurpExtender(IBurpExtender, IScannerCheck):

    # get references to callbacks, called when extension is loaded
    def registerExtenderCallbacks(self, callbacks):

        # get a local instance of callbacks object
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Cookie Decrypter")
        self._helpers = self._callbacks.getHelpers()

        # register as scanner object so we get used for active/passive scans
        self._callbacks.registerScannerCheck(self)

        stdout = PrintWriter(callbacks.getStdout(), True)
        stdout.println("""Successfully loaded Cookie Decrypter v""" + VERSION + """\n
Repository @ https://github.com/bellma101/cookie-decrypter/
Send feedback or bug reports to bellma101@0xfeed.io
Copyright (c) 2018 bellma101""")

        return

    # Get offset of cookie name in response. Requires array import above.
    # See https://github.com/PortSwigger/example-scanner-checks/blob/master/python/CustomScannerChecks.py
    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    # 'The Scanner invokes this method for each base request/response that is
    # passively scanned'
    # passing the self object as well for access to helper functions, etc.
    # java.util.List<IScanIssue> doPassiveScan(IHttpRequestResponse
    # baseRequestResponse)
    def doPassiveScan(self, baseRequestResponse):

        self._requestResponse = baseRequestResponse

        try:
            analyzedResponse = self._helpers.analyzeResponse(
                baseRequestResponse.getResponse())
            cookieList = analyzedResponse.getCookies()
            foundNSCCookies = []
            issues = list()

            # Iterate through cookies and check for Netscaler/BigIP
            for cookie in cookieList:
                cookieName = cookie.getName()

                # Check for Netscaler cookies
                if cookieName.lower().startswith("nsc_"):
                    foundNSCCookies.append(
                        cookieName + '=' + cookie.getValue())

                    try:
                        # Decrypt cookie
                        result = nsccookiedecrypt.decryptCookie(
                            cookieName + '=' + cookie.getValue())
                    except:
                        print 'Failed to decrypt Netscaler cookie.'

                    # Get match for issue highlighting
                    try:
                        offset = self._get_matches(
                            baseRequestResponse.getResponse(), cookieName +
                            '=' + cookie.getValue())
                    except:
                        print 'Get Netscaler matches failed.'

                    try:
                        # Set Netscaler issues
                        issues.append(NetscalerScanIssue(
                            self._requestResponse.getHttpService(),
                            self._helpers.analyzeRequest(
                                baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(
                                self._requestResponse, None, offset)],
                            result, cookieName, cookie.getValue()
                        ))
                    except:
                        print 'Failed to set Netscaler issue.'
                elif cookieName.lower().startswith("bigip"):
                    try:
                        result = f5cookiedecrypt.decryptCookie(cookie.getValue())

                        # Get match for issue highlighting
                        try:
                            offset = self._get_matches(
                                baseRequestResponse.getResponse(), cookieName +
                                '=' + cookie.getValue())
                        except:
                            print 'Get BigIP matches failed.'

                        # Set BigIP issues
                        try:
                            issues.append(BigIPScanIssue(
                                self._requestResponse.getHttpService(),
                                self._helpers.analyzeRequest(
                                    baseRequestResponse).getUrl(),
                                [self._callbacks.applyMarkers(
                                    self._requestResponse, None, offset)],
                                result, cookieName, cookie.getValue()
                            ))
                        except:
                            print 'Failed to set BigIP issue.'
                    except:
                        print 'Failed to decrypt BigIP cookie.'

                # Check for Flask cookies
                if str(cookieName.lower()) == 'session':
                    try:
                        result = {}
                        result = flaskcookiedecrypt.decode(cookie.getValue())
                        print result

                        # Get match for issue highlighting
                        try:
                            offset = self._get_matches(
                                baseRequestResponse.getResponse(), cookieName +
                                '=' + cookie.getValue())
                        except:
                            print 'Get Flask matches failed.'
                        # Set Flask issues
                        try:
                            issues.append(FlaskScanIssue(
                                self._requestResponse.getHttpService(),
                                self._helpers.analyzeRequest(
                                    baseRequestResponse).getUrl(),
                                [self._callbacks.applyMarkers(
                                    self._requestResponse, None, offset)],
                                result, cookieName, cookie.getValue()
                            ))
                        except:
                            print 'Failed to set Flask issue.'
                    except:
                        print 'Failed to decrypt Flask cookie.'

        except:
            print 'Failed to parse cookies.'

        if len(issues) > 0:
            return issues

        return None

    # 'The Scanner invokes this method when the custom Scanner check has
    # reported multiple issues for the same URL path'
    # 'The method should return -1 to report the existing issue only, 0 to
    # report both issues, and 1 to report the new issue only.'
    # consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

# 'This interface is used to retrieve details of Scanner issues. Extensions
# can obtain details of issues by registering an IScannerListener or
# by calling IBurpExtenderCallbacks.getScanIssues(). Extensions can also add
# custom Scanner issues by registering an IScannerCheck or calling
# IBurpExtenderCallbacks.addScanIssue(), and providing their own
# implementations of this interface. Note that issue descriptions and other
# text generated by extensions are subject to an HTML whitelist that allows
# only formatting tags and simple hyperlinks.'
# Here we are implementing our own custom scan issue to set scan issue
# information parameters and creating getters for each parameter


class NetscalerScanIssue(IScanIssue):
    # constructor for setting issue information
    def __init__(self, httpService, url, requestResponse, decodedCookie,
                 cookieName, rawCookieValue):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._cookieName = cookieName
        self._rawCookieValue = rawCookieValue
        self._decodedCookie = decodedCookie

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'Decrypted Netscaler Persistence Cookie'

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return 'Information'

    def getConfidence(self):
        return 'Certain'

    def getIssueBackground(self):
        return 'Citrix Netscaler persistence cookies use weak encryption, ' \
            'including a Caesar shift and XORing against fixed values.' \
            'These cookies are trivially decrypted and reveal the server ' \
            'name, IP address, and port.'

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        splitCookie = self._decodedCookie.split(':')
        description = 'A Netscaler persistence cookie was found and decrypted.<br>'
        description += '<br><b>Encrypted Cookie Value: </b>' + str(self._rawCookieValue)
        description += '<br><br><b>Decrypted values:</b>'
        description += '<br><ul><li><b>Server Name: </b>' + str(splitCookie[0])
        description += '</li><li><b>Server IP: </b>' + splitCookie[1]
        description += '</li><li><b>Server Port: </b>' + splitCookie[2] + '</li></ul>'
        return description

    def getRemediationDetail(self):
        return '<ul><li>https://www.citrix.com/blogs/2011/08/05/' \
            'secure-your-application-cookies-before-it-is-too-late/' \
            '</li><li>https://docs.citrix.com/en-us/netscaler/11/' \
            'traffic-management/load-balancing/load-balancing-' \
            'persistence/http-cookie-persistence.html</li></ul>'

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService


class BigIPScanIssue(IScanIssue):
    # constructor for setting issue information
    def __init__(self, httpService, url, requestResponse, decodedCookie,
                 cookieName, rawCookieValue):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._cookieName = cookieName
        self._rawCookieValue = rawCookieValue
        self._decodedCookie = decodedCookie

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'Decoded F5 BigIP Persistence Cookie'

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return 'Information'

    def getConfidence(self):
        return 'Certain'

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        splitCookie = self._decodedCookie.split(':')
        description = 'An F5 BigIP persistence cookie was found and decoded.<br>'
        description += '<br><b>Encoded Cookie Value: </b>' + str(self._rawCookieValue)
        description += '<br><br><b>Decoded values:</b>'
        description += '<br><ul><li><b>Server IP: </b>' + str(splitCookie[0])
        description += '</li><li><b>Server Port: </b>' + splitCookie[1] + '</li></ul>'
        return description

    def getRemediationDetail(self):
        return '<ul><li>https://support.f5.com/csp/article/K6917</li>'

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService


class FlaskScanIssue(IScanIssue):
    # constructor for setting issue information
    def __init__(self, httpService, url, requestResponse, decodedCookie,
                 cookieName, rawCookieValue):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._cookieName = cookieName
        self._rawCookieValue = rawCookieValue
        self._decodedCookie = decodedCookie

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'Decoded Flask Session Cookie'

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return 'Information'

    def getConfidence(self):
        return 'Certain'

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        description = 'A Flask session cookie was decoded.<br><br>'
        description += '<ul><li><b>Cookie Name: </b>' + str(self._cookieName)
        description += '</li>'
        description += '<li><b>Decoded Value: </b>' + str(self._decodedCookie)
        description += '</li></ul>'
        return description

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService
