from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import time
from datetime import datetime
import logging
import sys

#Variable Declaration
headless = False    # headless configuration (True/False)
colored_out = True  #Colored output in console (True/False). Keep it false if using Burp Suite Extension console
waiting_timer = True


#Check if the script launched from Burp or Directly 
if len(sys.argv) > 1:
    if "burp" in sys.argv[1:]:
        #Variable Declaration for Burp
        headless = True
        colored_out = False
        waiting_timer = False


# Set up Burp Suite proxy
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8080
PROXY = f"{PROXY_HOST}:{PROXY_PORT}"


# Write the output to the file
f = open("jwt_4B_Chrome_Headless_AutoLogin_Logs.txt", "a")
f.write(f"\n{datetime.now()} : Script Execution Started\n")

# Print the timer
def timer(x):
    global waiting_timer
    remaining_time = x
    if waiting_timer:
        while remaining_time > 0:
            print(f"Waiting for {remaining_time} seconds...", end='\r')
            time.sleep(1)
            remaining_time -= 1
        print(" " * len(f"Waiting for {remaining_time + 1} seconds..."), end='\r')
    else:
        print(f"  {datetime.now()} : Waiting for {remaining_time} seconds:", end=" ")
        while remaining_time > 0:
            print(f"{remaining_time}", end=" ", flush=True)
            time.sleep(1)
            remaining_time -= 1
        print("\r")

# Print the text
def print_me(x):
    global f,colored_out
    if colored_out:
        print(f"\x1b[1;34;40m {datetime.now()} : {x} \x1b[0m")
    else:
        print(f"  {datetime.now()} : {x}")
    f.write(f"{datetime.now()} : {x}\n")            

# Configure Chrome options to use Burp proxy
chrome_options = Options()
chrome_options.add_argument(f"--proxy-server=http://{PROXY}")
chrome_options.add_argument('--log-level=3') #https://stackoverflow.com/questions/2031163/when-to-use-the-different-log-levels
if headless:
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
print_me(f"Selenium Config = Headless: {headless}, colored_out: {colored_out}, waiting_timer: {waiting_timer}")        
print_me("Launching the browser")

# Initialize a headless Chrome browser instance with Burp proxy settings
driver = webdriver.Chrome(options=chrome_options)
#driver = webdriver.Chrome(options=chrome_options, service=Service(r'D:/WorkSpace/Burp Workspace/chromedriver.exe')) 
#Ref: https://chromedriver.chromium.org/home     https://bobbyhadz.com/blog/python-message-chromedriver-executable-needs-to-be-in-path  

# Navigate to the login page
print_me("Going to login URL")
driver.get('https://https://iamnotexist.test.com.sg')

# Wait for the login page to load
timer(6)
driver.implicitly_wait(50)

# Find the username and password fields using the find_element method
print_me("Key in credentials ")
username_input = driver.find_element('xpath', "//*[@id='txtUserID']")
password_input = driver.find_element('xpath', "//*[@id='txtPassword']")

# Enter your login credentials
username_input.send_keys('thisismyusername')
password_input.send_keys('thisismypassword')

# Submit the login form using the find_element method
submit_button = driver.find_element('xpath', "//*[@id='sub']")
submit_button.click()

# Wait for the login process to complete
timer(10)
driver.implicitly_wait(50)

# Close the browser
print_me("Exiting now")
driver.quit()
f.write(f"{datetime.now()} : Script Execution Completed\n")
f.close()
