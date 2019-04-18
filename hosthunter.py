#!/usr/bin/python3
#
#    | $$  | $$                      | $$    | $$  | $$                      | $$
#    | $$  | $$  /$$$$$$   /$$$$$$$ /$$$$$$  | $$  | $$ /$$   /$$ /$$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$
#    | $$$$$$$$ /$$__  $$ /$$_____/|_  $$_/  | $$$$$$$$| $$  | $$| $$__  $$|_  $$_/   /$$__  $$ /$$__  $$
#    | $$__  $$| $$  \ $$|  $$$$$$   | $$    | $$__  $$| $$  | $$| $$  \ $$  | $$    | $$$$$$$$| $$  \__/
#    | $$  | $$| $$  | $$ \____  $$  | $$ /$$| $$  | $$| $$  | $$| $$  | $$  | $$ /$$| $$_____/| $$
#    | $$  | $$|  $$$$$$/ /$$$$$$$/  |  $$$$/| $$  | $$|  $$$$$$/| $$  | $$  |  $$$$/|  $$$$$$$| $$
#    |__/  |__/ \______/ |_______/    \___/  |__/  |__/ \______/ |__/  |__/   \___/   \_______/|__/1
#
# Author  : Andreas Georgiou (superhedgy)
# Email   : ageorgiou@trustwave.com
# Twitter : @Mr_AndreasGeo
# Version: v1.5
#
# [+] Simple Usage Example:
#
#       $ python3 hosthunter.py <targets.txt>
#
#       $ cat vhosts.csv

# Standard Libraries
import argparse
import sys
import os
import ssl
import socket
import time
import re

# External Libraries
import OpenSSL
import urllib3
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Beta Feature
os.environ['http_proxy']=''

# Constants
_name="HostHunter"
_version="1.5"
_author="Andreas Georiou (superhedgy)"
_last_update= "20/11/2018"

# Options
chrome_opt = Options()
chrome_opt.add_argument("--ignore-certificate-errors")
chrome_opt.add_argument("--test-type")

#chrome_opt.add_argument("--headless")
DRIVER = 'chromedriver'
sc_path = 'screen_captures'
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_OPTIONAL
context.load_default_certs()
regx = "<li class=\"b_algo\"(.+?)</li>"
regx_h3 = "<h2><a hre=\"(.?)\""
regx_v4 = "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
regx_v6 = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
pattern_v4 = re.compile(regx_v4)
pattern_v6 = re.compile(regx_v6)
pattern=re.compile(regx)
# Hack to make things faster
socket.setdefaulttimeout(3)


## Argument Parser
parser = argparse.ArgumentParser(
description='|<--- HostHunter v1.5 - Help Page --->|',
epilog="Author: " + _author
)

parser.add_argument("-V","--version",help="Displays the currenct version.",action="store_true",default=False)
parser.add_argument("targets",help="Sets the path of the target IPs file." , type=str, default="targets.txt")
parser.add_argument("-f","--format",help="Choose between CSV and TXT output file formats.", default="csv")
parser.add_argument("-o","--output", help="Sets the path of the output file.", type=str,default="vhosts.csv")
parser.add_argument("-b","--bing",help="Use Bing.com search engine to discover more hostnames associated with the target IP addreses.",action="store_true",default=False)
parser.add_argument("-sc","--screen-capture",help="Capture a screen shot of any associated Web Applications.",action="store_true",default=False)
args = parser.parse_args()

if args.format.lower() != "txt" and args.format.lower() != "csv":
    print ("\nUnrecognised file format argument. Choose between 'txt' or 'csv' output file formats.\n")
    print("Example Usage: python3 hosthunter.py targets.txt -f txt ")
    exit()

if args.version:
    print("HostHunter version",version)
    print("Last Updated:",_last_update)
    print("Author:", _author)
    exit()

# Targets Input File
if not os.path.exists(args.targets):
    print("\n[*] Error: targets file",args.targets,"does not exist.\n")
    exit()

if os.path.exists(args.output):
    print("\n[?] {} file already exists, would you like to overwrite it?".format(args.output))
    answer = input("Answer with [Y]es or [N]o : ").lower()
    if (answer == 'no' or answer == 'n'):
        exit()

targets = open(args.targets,"rt") # Read File
vhostsf = open(args.output, "wt") # Write File
appsf = open("webapps.txt", "wt") # Write File

if args.format.lower() == "csv":
    vhostsf.write("\"" + "IP Address" + "\",\"" + "Port/Protocol" + "\",\"" + "Domains" +  "\",\""
    + "Operating System" + "\",\"" + "OS Version" + "\",\"" + "Notes" +  "\"\n") #vhosts.csv Header

def display_banner():
    banner=(
        "                                                                             \n"
        " | $$  | $$                      | $$    | $$  | $$                      | $$\n"
        " | $$  | $$  /$$$$$$   /$$$$$$$ /$$$$$$  | $$  | $$ /$$   /$$ /$$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$\n"
        " | $$$$$$$$ /$$__  $$ /$$_____/|_  $$_/  | $$$$$$$$| $$  | $$| $$__  $$|_  $$_/   /$$__  $$ /$$__  $$\n"
        " | $$__  $$| $$  \ $$|  $$$$$$   | $$    | $$__  $$| $$  | $$| $$  \ $$  | $$    | $$$$$$$$| $$  \__/\n"
        " | $$  | $$| $$  | $$ \____  $$  | $$ /$$| $$  | $$| $$  | $$| $$  | $$  | $$ /$$| $$_____/| $$\n"
        " | $$  | $$|  $$$$$$/ /$$$$$$$/  |  $$$$/| $$  | $$|  $$$$$$/| $$  | $$  |  $$$$/|  $$$$$$$| $$\n"
        " |__/  |__/ \______/ |_______/    \___/  |__/  |__/ \______/ |__/  |__/   \___/   \_______/|__/  " + _version + "\n"
    )

    print ("%s" % banner)
    print ("\n" ,"HostHunter: ", _version)
    print (" Author : ageorgiou@trustwave.com")
    print (" Twitter: @mr_andreasgeo")
    print ("\n" + "|" + "-" * 95 + "|", end = "\n")

class target:
    def __init__(self,address):
        self.address = address
        self.hname = []
        self.apps = []
        self.ipv6 = False

def take_screenshot(IP,port):
    if port == "443":
        url="https://" + IP
    else:
        url="http://" + IP+":"+port
    print ("Printing the SC URL",url)
    try:
        #driver.implicitly_wait(15)
        driver.get(url)
        print ("Taking Screenshot:",url)
        driver.save_screenshot(sc_path+"/"+IP+"_"+port+".png")
    except:
        pass

def validate(targ):
    #print(IP)
    if not bool(re.match(pattern_v4,targ.address)):
        if bool(re.match(pattern_v6,targ.address)) == True:
            targ.ipv6 = True
        else:
            print ("\n\"",targ.address,"\" is not a valid IPv4 or IPv6 address.")
            return False
    else:
        True

# Main Function - Read IPs from <targets.txt> file
def main(argc):
    counter=0

    for ip in targets:
        ip=ip.replace("\n","")
        hostx = target(ip)
        if validate(hostx) == False:
            continue

        print ("\n[+] Target: %s" % hostx.address)
        # Querying HackerTarget.com API
        try:
            http = urllib3.PoolManager()
        #    r3 = http.request('GET', 'https://api.hackertarget.com/reverseiplookup/?q=%s' % ip,decode_content=True).read().decode("UTF-8")
        #    print (r3)
        #    r2 = urllib3.request.urlopen('https://api.hackertarget.com/reverseiplookup/?q=%s' % ip).read().decode("UTF-8")
            r2 = http.request('GET', 'https://api.hackertarget.com/reverseiplookup/?q=%s' % ip,decode_content=True).read().decode("UTF-8")
            if (r2.find("No DNS A records found")==-1) and (r2.find("API count exceeded")==-1 and r2.find("error")==-1):
                for host in r2.split('\n'):
                    if (host=="") or (host in hostx.hname):
                        pass
                    else:
                        hostx.hname.append(host)
            # Add API count exceed detection
            else:
                pass
        except (urllib3.connection.ConnectionError,urllib3.exceptions.ConnectTimeoutError,urllib3.exceptions.TimeoutError) as e:
            print ("[*] Error: connecting with HackerTarget.com API")

        # Querying Bing.com
        if args.bing == True:
            try:
                http = urllib3.PoolManager()
                #r3 = urllib3.request.urlopen('https://www.bing.com/search?q=ip%%3a%s' % ip).read().decode("UTF-8")
                r3 = http.request('GET','https://www.bing.com/search?q=ip%%3a%s' % ip,decode_content=True)
                response= r3.data.decode('utf-8')
                bing_results = re.findall(pattern,response)
                #print (bing_results)
                for item in bing_results:
                    url = re.findall("(http(s)?://[^\s]+)",item)[0][0]
                    item = re.sub("\"","",url)
                    hostx.apps.append(item)
                    host = re.sub("(http(s)?://)","",item)
                    host2 = re.sub("/(.)*","",host)
                #    print (host);
                    if (host2=="") or (host2 in hostx.hname):
                        pass
                    else:
                        hostx.hname.append(host2)
            except (urllib3.connection.ConnectionError,urllib3.exceptions.ConnectTimeoutError,urllib3.exceptions.TimeoutError) as e:
                print ("[*] Error: connecting with Bing.com")

        # Capture Screenshots with -cs option
        if args.screen_capture == True:
            take_screenshot(ip,"80")
            take_screenshot(ip,"443")
            take_screenshot(ip,"8080")
        # Fetch SSL Certificates
        try:
            cert=ssl.get_server_certificate((ip, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            cert_hostname=x509.get_subject().CN
            # Add New HostNames to List
            for host in cert_hostname.split('\n'):
                if (host=="") or (host in hostx.hname):
                    pass
                else:
                    hostx.hname.append(host)
        except (requests.ConnectionError,requests.Timeout,socket.error,socket.timeout) as e:
            pass

        if hostx.hname:
            print ("[+] Hostnames: ", end = "\n")
            for item in hostx.hname:
                print (item)
                # Write output to .TXT file
                if args.format.lower()=='txt':
                    vhostsf.write(item + "\n")
                counter += 1

            # Write output to .CSV file
            if args.format.lower() == 'csv':
                hostnames = ','.join(hostx.hname) # Merging the lists prooved Faster than list iterations
                row = "\"" + ip + "\"," + "\"443/tcp\"" + "," + "\"" + hostnames + "\",\"\",\"\",\"\"" + "\n"
                vhostsf.write(row)

                if (args.bing == True and hostx.apps):
                    apps = ','.join(hostx.apps)
                    row = "\"" + hostx.address + "\"," + "\"443/tcp\"" + "," + "\"" + apps + "\"" + "\n"
                    appsf.write(row)

        else:
            print ("[-] Hostnames: no results ")
            continue

        if (args.bing == True and hostx.apps):
            print ("[+] Web Apps:")
            for url in hostx.apps:
                print (url)

        # END FOR LOOP
    # END IF
    targets.close()

    if args.screen_capture == True:
        driver.quit()
    # IPV6 https://[%ip6]
    #  Robtex
    #  https://freeapi.robtex.com/pdns/reverse/$ip

    print ("\n" + "|" + "-" * 95 + "|", end = "\n\n")
    print ("  Reconnaissance Completed!", end = "\n\n")
    if counter==0:
        print ("  0 hostname was discovered in %s sec" % (round(time.time() - start_time,2)), end = "\n\n")
    else:
        print ("  %s hostnames were discovered in %s sec" % (counter,round(time.time() - start_time,2)), end = "\n\n")
    print ("|" + "-" * 95 + "|")
#End of Main Function

if __name__ == "__main__":
    start_time = time.time() # Start Counter
    display_banner() # Banner

    if args.screen_capture == True:
        driver = webdriver.Chrome(executable_path=DRIVER,chrome_options=chrome_opt)
        driver.set_page_load_timeout(10)
        if not os.path.exists(sc_path):
            os.makedirs(sc_path)
        print ("    Screenshots saved at: ",os.getcwd()+ "/" +sc_path)
        print ("|" + "-" * 95 + "|", end = "\n\n")

    main(sys.argv)
#EOF
