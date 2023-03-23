"""
By: V9Y1nf0S3C (https://github.com/V9Y1nf0S3C/)

Purpose:
    1.Fetch the access_token, refresh_token from burp response
    2.Update the cookue jar

Scope: Proxy, Repeater, Intruder (remaining to be tested)

This script is modified from the below reference as per my needs.

Ref:
https://www.ryanwendel.com/2019/09/07/using-burp-suites-cookie-jar-for-json-web-tokens/

"""

from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
from burp import ICookie
import re
import datetime

class Cookie(ICookie):

    def getDomain(self):
        return self.cookie_domain

    def getPath(self):
        return self.cookie_path

    def getExpiration(self):
        return self.cookie_expiration

    def getName(self):
        return self.cookie_name

    def getValue(self):
        return self.cookie_value

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None,
                 cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("V9Y-JWT(1)-Fetch JWT & Refresh Token(Get from response)")
        callbacks.registerHttpListener(self)
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        # Only process responses
        if messageIsRequest:
            return

        # Check if the response has a Refresh/Access token
        response = self._helpers.analyzeResponse(currentMessage.getResponse())
        headers = response.getHeaders()
        body = currentMessage.getResponse()[response.getBodyOffset():].tostring()
        refresh_token = None
        access_token = None
        is_it_json = None
        
        # Check if the response is JSON
        for header in headers:
            if "Content-Type" in header and "application/json" in header:
                # The response type is application/json
                self._callbacks.issueAlert("Response is of type application/json")
                is_it_json = True
                break      
        if not is_it_json:       
            return
        
        # Check if the response has refresh_token/access_token
        if "refresh_token" in body.lower():
            refresh_token = self._get_refresh_token(body)
            print("[" + datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S") + "] Refresh_token found. Here is the value: " + refresh_token )#+ "\n")
        if "access_token" in body.lower():
            access_token = self._get_jwt_token(body)
            print("[" + datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S") + "] Access_token found. Here is the value: " + access_token[-90:] )#+ "\n")

        # Update the refresh_token/access_token tokens in cookiejar 
        if refresh_token:
            cookie = Cookie("localhost", "refresh_token", refresh_token,  "/", None)
            self._callbacks.updateCookieJar(cookie)
        
        if access_token:
            cookie = Cookie("localhost", "access_token", access_token,  "/", None)
            self._callbacks.updateCookieJar(cookie)
        
        return

    def _get_refresh_token(self, response_body):
        # Regex pattern to extract refresh token from response body
        pattern = r"refresh_token\":\"(.+?)\""

        matches = re.search(pattern, response_body)
        if matches:
            refresh_token = matches.group(1)
            return refresh_token
        else:
            return None
    def _get_jwt_token(self, response_body):
        # Regex pattern to extract access token from response body
        pattern = r"access_token\":\"(.+?)\""

        matches = re.search(pattern, response_body)
        if matches:
            access_token = matches.group(1)
            return access_token
        else:
            return None
