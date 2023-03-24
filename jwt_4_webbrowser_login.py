from burp import IBurpExtender, ISessionHandlingAction, IExtensionHelpers
from java.io import PrintWriter
import subprocess
import datetime

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    
    def	registerExtenderCallbacks(self, callbacks):
        # Save reference to Burp's callback methods
        self._callbacks = callbacks
        
        # Save reference to Burp's helper methods
        self._helpers = callbacks.getHelpers()
        
        # Register extension as a session handling action
        callbacks.registerSessionHandlingAction(self)
        
        # Set extension name
        callbacks.setExtensionName("V9Y-JWT(4)-Web Browser Login(Chrome Headless)")
        
        # Get output stream for console messages
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        
        # Log initialization message
        self._stdout.println("V9Y-JWT(4)-Web Browser Login(Chrome Headless) initialized.")
    
    def getActionName(self):
        return "V9Y-JWT(4)-Web Browser Login(Chrome Headless)"
    
    def performAction(self, currentRequest, macroItems):
        # Call the Python script using subprocess
        self._callbacks.issueAlert("Session Expired. Selenium is in action.")
        print("\n[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] 1.Python script going to launch-----------------------------" )

        # Build the command to execute the Python script
        command = ["python3", "E:\\Burp\\HeadlessLogin\\jwt_4B_Chrome_Headless_AutoLogin.py","burp"]
        
        # Execute the command and capture the output
        output = subprocess.check_output(command)#, stderr=subprocess.STDOUT)

        # Log the output in Burp extension logs
        print(output.rstrip())
        
        # Log message to indicate that the script has been called
        print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] 2.Python script executed-----------------------------" )
