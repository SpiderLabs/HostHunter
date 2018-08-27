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
# Version: v1.1
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
version="v1.1"
these_regex="<cite>(.+?)</cite>"
counter=0
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_OPTIONAL
context.load_default_certs()
regx = "<cite>(.+?)</cite>"
pattern=re.compile(regx)
# Write to output file
path = sys.argv[1]
targets = open(path,"rt")
# .CSV file output
vhostsf = open("vhosts.csv", "wt")
vhostsf.write("\"" + "IP Address" + "\",\"" + "Port/Protocol" + "\",\"" + "Domains" +  "\",\"" +
"Operating System" + "\",\"" + "OS Version" + "\",\"" + "Notes" +  "\"\n") #vhosts.csv Header

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
print ("\n" ,"nter", version)
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
    try:
        r3 = urllib.request.urlopen('https://www.bing.com/search?q=ip%%3a%s' % ip).read().decode("UTF-8")
        bing_results = re.findall(pattern,r3)

        #print (r3)
        #print (bing_results)

        for item in bing_results:
            #host = item.replace('<strong>','')
            item2 = re.sub("<.[a-z]+>","",item)
            host  = re.sub("http[s]://","",item2)
            if "\/" in host:
                print ('TEST')
            print(host)
            if (host=="") or (host in hname):
                pass
            else:
                #print (host)
                hname.append(host)
    except urllib.error.HTTPError as e:
        print ("[*] Error accessing Bing.com")

    exit()

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
            counter += 1

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
