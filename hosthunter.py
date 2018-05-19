#
# hosthunter.py
# A simple & efficient tool to identify virtual hostnames.
#
# author: Andreas Georgiou
# email : ageorgiou@trustwave.com
# version: v1.0
#
# To do list:
#   [ ] Search Bing.com
#   [x] Capture hostnames from SSL certificates (Invalid and Valid)
#   [x] Basic verification of hostnames
#   [x] Hackertarget.com API
#   [ ] FreeAPI Robtex
#
# Tested with Python 2.6.5
#
# Usage Example:
#
# $ python hosthunter.py <targets.txt>
#
# $ cat vhosts.txt
#

import sys
import ssl
import socket
import time
import requests
import OpenSSL
import urllib2
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

path = sys.argv[1]
targets = open(path,"r")
vhostsf = open("vhosts.csv", "wb")
counter=0
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_OPTIONAL
context.load_default_certs()

start_time = time.time()
print "\n HostHunter v1.0"
print " Author: ageorgiou@trustwave.com\n"

# Read targets.txt file
for ip in targets:
    ip=ip.replace("\n","")
    print "\n[+] Target: %s" % ip

# Querying HackerTarget.com API
    try:
        r2 = urllib2.urlopen('https://api.hackertarget.com/reverseiplookup/?q=%s' % ip).read()
        if r2.find("No DNS A records found") == -1:
            hostnames=r2
        else:
            hostnames=''
    except urllib2.HTTPError as e:
        print "Error connecting with HackerTarget.com API"

# Fetch SSL certificate
    try:
        # Hack to make things faster
        r = requests.get('https://%s' % ip, timeout=5,verify=False)

        cert=ssl.get_server_certificate((ip, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_hostname=x509.get_subject().CN
        hostnames +=cert_hostname
        print cert_hostname
    except (requests.ConnectionError,requests.Timeout,socket.error) as e:
        pass

    if hostnames != "":
        print "[+] Hostnames: \n%s" % hostnames
        row = ip + "," + "443/tcp" + "," + hostnames.replace("\n"," ") + "\n"
        counter += 1
        vhostsf.write(row)
    else:
        print "[-] Hostnames: no results "
        continue

# END IF
targets.close()

##### Expiramnetal - Bing.com Implementation #####

'''
ht = requests.get('https://freeapi.robtex.com/ipquery/'%ip)
print ht.content;

### Delete Between Comments ###
'''

print "\n\n Reconnaissance Completed!\n"
print "\n %s hostnames were discovered in %s sec\n\n" % (counter,round(time.time() - start_time,2))
