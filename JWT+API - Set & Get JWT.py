# python imports
import re
import sys
import datetime

# Burp specific imports
from burp import IBurpExtender
from burp import IHttpListener
from burp import ISessionHandlingAction
from java.io import PrintWriter
from burp import ICookie

# For using the debugging tools from
# https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

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

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration


class BurpExtender(IBurpExtender, IHttpListener, ISessionHandlingAction):


    # Define config and gui variables
    cookieName = 'access_token'
    cookieDomain = 'localhost'
    header_name_1 = 'Authorization: Bearer'
    header_name_2 = 'custom_auth_header:'

    # Define some cookie functions
    def deleteCookie(self, domain, name):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None,  cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_nuked)
                break

    def createCookie(self, domain, name, value, path=None, expiration=None):
        cookie_to_be_created = Cookie(domain, name, value,  path, expiration)
        self.callbacks.updateCookieJar(cookie_to_be_created)

    def setCookie(self, domain, name, value):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                cookie_to_be_set = Cookie(cookie.getDomain(), cookie.getName(), value,  cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_set)
                break

    def getCookieValue(self, domain, name):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                return cookie.getValue()

    def getCookieValueCustomPath(self, domain, name, path):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name and (str(cookie.getPath()).lower().find(path.lower())>-1):
                return cookie.getValue()


    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self.callbacks = callbacks

        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("V9Y - JWT+API - Set&Get JWT")

        # register ourselves a Session Handling Action
        callbacks.registerSessionHandlingAction(self)

        # register ourselves a HttpListener
        callbacks.registerHttpListener(self)

        # Used by the custom debugging tools
        sys.stdout = callbacks.getStdout()

        print("DEBUG: V9Y - JWT+API - Set&Get JWT - Enabled!")

        return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        # Only process responses
        if messageIsRequest:
            return

        # Check if the response has a Refresh/Access token
        response = self.helpers.analyzeResponse(currentMessage.getResponse())
        headers = response.getHeaders()
        is_it_json = None
        url = self.helpers.analyzeRequest(currentMessage).getUrl().toString()
        third_slash = url.find('/', url.find('/', url.find('/') + 1) + 1)
        
        # Check if the response is JSON
        for header in headers:
            if "Content-Type" in header and "application/json" in header:
                # The response type is application/json
                is_it_json = True
                break      
        if not is_it_json:       
            return

        body = currentMessage.getResponse()[response.getBodyOffset():].tostring()
        access_token = None

        # Check if the response has access_token
        if "access_token" in body.lower():
            access_token = self._get_jwt_token(body)

        # Update the access_token tokens in cookiejar 
        if access_token:

            path = "/"
            path_exist_in_req = False

           # Check if the request contains the desired header
            request = currentMessage.getRequest()
            headers = self.helpers.analyzeRequest(request).getHeaders()
            for header in headers:
                if re.search("Path:.*", header, re.IGNORECASE):
                    path_exist_in_req = True
                    continue

            if path_exist_in_req:
                request_headers = self.helpers.bytesToString(request).split('\r\n')
                for req_header in request_headers:
                    if re.search("Path:.*", req_header, re.IGNORECASE):
                        path = re.search("Path:(.*)", req_header).group(1).strip()
                        cookie = Cookie("localhost", "access_token", access_token,  path, None)
                        self.callbacks.updateCookieJar(cookie)
                        print("[" + datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + "] + READ_RESPONSE:access_token - [Tool:" + str(toolFlag) + "] [Token(-40):" + access_token[-40:] + "] [BCJ-Path:" + path+ "] [ReqURL:" + url[third_slash:]+ "]")
            else:            
                cookie = Cookie("localhost", "access_token", access_token,  path, None)
                self.callbacks.updateCookieJar(cookie)
                print("[" + datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S") + "] + READ_RESPONSE:access_token - [Tool:" + str(toolFlag) + "] [Token(-40):" + access_token[-40:] + "] [BCJ-Path:" + path+ "] [ReqURL:" + url[third_slash:]+ "]")
        return

    def _get_jwt_token(self, response_body):
        # Regex pattern to extract access token from response body
        pattern = r"access_token\":\"(.+?)\""

        matches = re.search(pattern, response_body)
        if matches:
            access_token = matches.group(1)
            return access_token
        else:
            return None

    # Implement ISessionHandlingAction
    def getActionName(self):
        return "V9Y - JWT+API - MODIFY_REQUEST"

    def performAction(self, current_request, macro_items):
        # grab some stuff from the current request
        req_text = self.helpers.bytesToString(current_request.getRequest())

        #Check for path
        
        # Get the URL from the request
        url = self.helpers.analyzeRequest(current_request).getUrl().toString()

        # Trim the URL
        third_slash = url.find('/', url.find('/', url.find('/') + 1) + 1)
        last_slash = url.rfind('/')
        path = url[third_slash:last_slash]
        
        # grab jwt from cookie jar
        jwt = self.getCookieValueCustomPath(self.cookieDomain, self.cookieName, path)
        
        if jwt == None:
            last_but_second_slash = url.rfind('/', 0, url.rfind('/'))
            path = url[third_slash:last_but_second_slash]
            jwt = self.getCookieValueCustomPath(self.cookieDomain, self.cookieName, path)

        if jwt == None:
            path = "NONE-FIFO"
            jwt = self.getCookieValue(self.cookieDomain, self.cookieName)

        # does a value exist yet?
        if jwt != None:
            # replace the old token with the stored value
            header_selected = "NONE"
            header_replace = "No header found to replace. No header founbd to replace. No header founbd to replace. No header founbd to replace. No header founbd to replace. "
            request = current_request.getRequest()
            headers = self.helpers.analyzeRequest(request).getHeaders()
            for header in headers:
                if re.search(self.header_name_1 + ".*", header, re.IGNORECASE):
                    header_replace = "%s %s" % (self.header_name_1, jwt)
                    req_text = re.sub(r"\r\n" + self.header_name_1 + ".*\r\n", "\r\n" + header_replace + "\r\n" , req_text, flags=re.IGNORECASE)
                    header_selected = self.header_name_1
                    continue
                elif re.search(self.header_name_2 + ".*", header, re.IGNORECASE):
                    header_replace = "%s %s" % (self.header_name_2, jwt)
                    req_text = re.sub(r"\r\n" + self.header_name_2 + ".*\r\n", "\r\n" + header_replace + "\r\n" , req_text, flags=re.IGNORECASE)
                    header_selected = self.header_name_2
                    continue
            # set the current request
            if header_selected == "NONE":
                print("[" + datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S") + "] - NO_AUTH_HEADER_IN_REQUEST: Request doesn't have known JWT header - [ReqURL:" + url[third_slash:]+ "]")
            else:
                current_request.setRequest(self.helpers.stringToBytes(req_text))
                print("[" + datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S") + "] MODIFY_REQUEST:access_token from BCJ - [Token(-25):" + header_replace[-25:] + "] [" +  header_selected + "] [BCJ-Path:" + path + "] [ReqURL:" + url[third_slash:]+ "]")
            

try:
    FixBurpExceptions()
except:
    pass