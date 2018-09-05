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
# Author : Andreas Georgiou (superhedgy)
# Email  : ageorgiou@trustwave.com
# Version: v1.5
#
#
# [+] Usage Example:
#
#       $ python3 hosthunter.py <targets.txt>
#
#       $ cat vhosts.csv
#

import argparse
import sys
import ssl
import socket
import time
import requests
import OpenSSL
import urllib
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Constants
version="1.5"
last_update= "27/10/2018"
author= "Andreas Georgiou (superhedgy)"
these_regex="<cite>(.+?)</cite>"
counter=0
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_OPTIONAL
context.load_default_certs()
regx = "<cite>(.+?)</cite>"
pattern=re.compile(regx)

## Argument Parser
parser = argparse.ArgumentParser(
description='< HostHunter Help Page >',
epilog="Author: ageorgiou@trustwave.com"
)
## nargs='?' to capture mutliple variables
parser.add_argument("-V","--version",help="Displays the currenct version.",action="store_true",default=False)
parser.add_argument("targets",help="Sets the path of the target IPs file." , type=str, default="targets.txt")
parser.add_argument("-f","--format",help="Choose between CSV and TXT output file formats.", default="csv")
parser.add_argument("-o","--output", help="Sets the path of the output file.", type=str,default="vhosts.csv")
parser.add_argument("-b","--bing",help="Use Bing.com search engine to discover more hostnames associated with the target IP addreses.",action="store_true",default=False)
args = parser.parse_args()

if args.format.lower() != "txt" and args.format.lower() != "csv":
    print ("\nUnrecognised file format argument. Choose between 'txt' or 'csv' output file formats.\n")
    print("Example Usage: python3 hosthunter.py targets.txt -f txt ")
    exit()

if args.version:
    print("HostHunter version",version)
    print("Last Updated:",last_update)
    print("Author:", author)
    exit()

# Targets Input File
targets = open(args.targets,"rt")
# # Write to a .CSV file
vhostsf = open(args.output, "wt")

if args.format.lower() == "csv":
    vhostsf.write("\"" + "IP Address" + "\",\"" + "Port/Protocol" + "\",\"" + "Domains" +  "\",\""
    + "Operating System" + "\",\"" + "OS Version" + "\",\"" + "Notes" +  "\"\n") #vhosts.csv Header

banner=(
    " | $$  | $$                      | $$    | $$  | $$                      | $$\n"
    " | $$  | $$  /$$$$$$   /$$$$$$$ /$$$$$$  | $$  | $$ /$$   /$$ /$$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$\n"
    " | $$$$$$$$ /$$__  $$ /$$_____/|_  $$_/  | $$$$$$$$| $$  | $$| $$__  $$|_  $$_/   /$$__  $$ /$$__  $$\n"
    " | $$__  $$| $$  \ $$|  $$$$$$   | $$    | $$__  $$| $$  | $$| $$  \ $$  | $$    | $$$$$$$$| $$  \__/\n"
    " | $$  | $$| $$  | $$ \____  $$  | $$ /$$| $$  | $$| $$  | $$| $$  | $$  | $$ /$$| $$_____/| $$\n"
    " | $$  | $$|  $$$$$$/ /$$$$$$$/  |  $$$$/| $$  | $$|  $$$$$$/| $$  | $$  |  $$$$/|  $$$$$$$| $$\n"
    " |__/  |__/ \______/ |_______/    \___/  |__/  |__/ \______/ |__/  |__/   \___/   \_______/|__/  " + version + "\n"
)

print ("%s" % banner)
print ("\n" ,"HostHunter: ", version)
print (" Author: ageorgiou@trustwave.com\n")
start_time = time.time()
# Read targets.txt file
for ip in targets:
    hname = [] #Decleare List
    ip=ip.replace("\n","")
    print ("\n[+] Target: %s" % ip)
    hostnames=''

    # Querying HackerTarget.com API
    try:
        r2 = urllib.request.urlopen('https://api.hackertarget.com/reverseiplookup/?q=%s' % ip).read().decode("UTF-8")
        if (r2.find("No DNS A records found")==-1) and (r2.find("API count exceeded")==-1):
            for host in r2.split('\n'):
                if (host=="") or (host in hname):
                    pass
                else:
                    hname.append(host)
        else:
            pass
    except urllib.error.HTTPError as e:
        print ("[*] Error connecting with HackerTarget.com API")


    # Querying Bing.com
    if args.bing == True:
        try:
            r3 = urllib.request.urlopen('https://www.bing.com/search?q=ip%%3a%s' % ip).read().decode("UTF-8")
            bing_results = re.findall(pattern,r3)
            for item in bing_results:
                item2 = re.sub("<.[a-z]+>","",item)
                host  = re.sub("http[s]://","",item2)
                if "\/" in host:
                    print ('TEST')
                    print(host)
                if (host=="") or (host in hname):
                    pass
                else:
                    hname.append(host)
        except urllib.error.HTTPError as e:
            print ("[*] Error accessing Bing.com")

# Fetch SSL certificate
    try:
        # Hack to make things faster
        r = requests.get('https://%s' % ip, timeout=4,verify=False)
        cert=ssl.get_server_certificate((ip, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_hostname=x509.get_subject().CN

        #### Add Items to List ####
        for host in cert_hostname.split('\n'):
            if (host=="") or (host in hname):
                pass
            else:
                hname.append(host)
    except (requests.ConnectionError,requests.Timeout,socket.error) as e:
        pass

    if hname:
        print ("[+] Hostnames: ", end = "\n")
        for item in hname:
            print (item)
            vhostsf.write(item + "\n")
            counter += 1

        if args.format.lower() == 'csv':
            # Write output to .CSV file
            hostnames = ','.join(hname) # Merging the lists prooved Faster than list iterations
            row = "\"" + ip + "\"," + "\"443/tcp\"" + "," + "\"" + hostnames + "\",\"\",\"\",\"\"" + "\n"
            vhostsf.write(row)

    else:
        print ("[-] Hostnames: no results ")
        continue

# END IF
targets.close()

# IPV6 https://[%ip6]
#  Robtex
#  https://freeapi.robtex.com/pdns/reverse/$ip

print ("\n" + "|" + "-" * 65 + "|", end = "\n\n")
print ("  Reconnaissance Completed!", end = "\n\n")
if counter==0:
    print ("  1 hostname was discovered in %s sec" % (round(time.time() - start_time,2)), end = "\n\n")
else:
    print ("  %s hostnames were discovered in %s sec" % (counter,round(time.time() - start_time,2)), end = "\n\n")

print ("|" + "-" * 65 + "|")
