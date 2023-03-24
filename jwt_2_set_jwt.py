"""
By: V9Y1nf0S3C (https://github.com/V9Y1nf0S3C/)

Purpose:
    1.Get the access_token from the Burp cookie jar
    2.Set the access_token in burp request (Session handling Rules)

Scope: as defined in Session handling Rules

This script is modified from the below reference as per my needs.

Ref:
https://www.ryanwendel.com/2019/09/07/using-burp-suites-cookie-jar-for-json-web-tokens/

"""
# python imports
import re
import sys

# Burp specific imports
from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import ICookie
import datetime

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

class BurpExtender(IBurpExtender, ISessionHandlingAction):

	#
	# Define config and gui variables
	#
	cookieName = 'access_token'
	cookieDomain = 'localhost'
	header_name = 'Authorization: Bearer'

	#
	# Define some cookie functions
	#
	def deleteCookie(self, domain, name):
		cookies = self.callbacks.getCookieJarContents()
		for cookie in cookies:
			#self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))	
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
			#self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))	
			if cookie.getDomain() == domain and cookie.getName() == name:
				cookie_to_be_set = Cookie(cookie.getDomain(), cookie.getName(), value,  cookie.getPath(), cookie.getExpiration())
				self.callbacks.updateCookieJar(cookie_to_be_set)
				break

	def getCookieValue(self, domain, name):
		cookies = self.callbacks.getCookieJarContents()
		for cookie in cookies:
			#self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))	
			if cookie.getDomain() == domain and cookie.getName() == name:
				return cookie.getValue()


	#
	# implement IBurpExtender
	#
	def	registerExtenderCallbacks(self, callbacks):
		# keep a reference to our callbacks object
		self.callbacks = callbacks

		# obtain an extension helpers object
		self.helpers = callbacks.getHelpers()

		# set our extension name
		callbacks.setExtensionName("V9Y-JWT(2)-Set JWT(update request)")

		# register ourselves a Session Handling Action
		callbacks.registerSessionHandlingAction(self)

		# Used by the custom debugging tools
		sys.stdout = callbacks.getStdout()

		print("DEBUG: V9Y-JWT(2)-Set JWT(update request) - Enabled!")

		return

	#
	# Implement ISessionHandlingAction
	#
	def getActionName(self):
		return "V9Y-JWT(2)-Set JWT(update request)"

	def performAction(self, current_request, macro_items):
		# grab some stuff from the current request
		req_text = self.helpers.bytesToString(current_request.getRequest())

		# grab jwt from cookie jar
		jwt = self.getCookieValue(self.cookieDomain, self.cookieName)

		# does a value exist yet?
		if jwt != None:
			# replace the old token with the stored value
			header_replace = "%s %s" % (self.header_name, jwt)
			req_text = re.sub(r"\r\n" + self.header_name + ".*\r\n", "\r\n" + header_replace + "\r\n" , req_text)

			# set the current request
			current_request.setRequest(self.helpers.stringToBytes(req_text))
			print("[" + datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S") + "] JWT token fetched from Burp Cookie jar & updated the request. Token: " + header_replace[-90:] )


try:
	FixBurpExceptions()
except:
	pass