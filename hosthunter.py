#!/usr/bin/python3
#
# | $$  | $$                              | $$  | $$
# | $$  | $$                      | $$    | $$  | $$                      | $$
# | $$  | $$  /$$$$$$   /$$$$$$$ /$$$$$$  | $$  | $$ /$$   /$$ /$$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$
# | $$$$$$$$ /$$__  $$ /$$_____/|_  $$_/  | $$$$$$$$| $$  | $$| $$__  $$|_  $$_/   /$$__  $$ /$$__  $$
# | $$__  $$| $$  \ $$|  $$$$$$   | $$    | $$__  $$| $$  | $$| $$  \ $$  | $$    | $$$$$$$$| $$  \__/
# | $$  | $$| $$__| $$ \____  $$  | $$ /$$| $$  | $$| $$__| $$| $$  | $$  | $$ /$$| $$_____/| $$
# | $$  | $$|  $$$$$$/ /$$$$$$$/  |  $$$$/| $$  | $$|  $$$$$$/| $$  | $$  |  $$$$/|  $$$$$$$| $$
# |__/  |__/ \______/ |_______/    \___/  |__/  |__/ \______/ |__/  |__/   \___/   \_______/|__/  v1.5
#
# Author  : Andreas Georgiou (@superhedgy)
# Email   : ageorgiou@trustwave.com
# Twitter : @superhedgy
# Version: v2.0
#
# [+] Simple Usage Example:
#
#       $ python3 hosthunter.py <target_ips.txt>
#
#       $ cat vhosts.csv

# Standard Python Libraries
import argparse
import sys
import os
import ssl
import socket
import signal
import platform
import ipaddress
import re
from datetime import datetime
from time import time, sleep
from validator_collection import checkers # New Library
# External Python Libraries
import OpenSSL
import urllib3
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Constants
__version__ = "v2.0"
__author__ = "Andreas Georgiou (@superhedgy)"

global appsf
global vhostsf

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_OPTIONAL
context.load_default_certs()
regx = "<li class=\"b_algo\"(.+?)</li>"
regx_h3 = "<h2><a hre=\"(.?)\""
#pattern_url = re.compile(r"https?://(www\.)?|(/.*)?")
pattern = re.compile(regx)

custom_headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
}
# Hack to make things faster
socket.setdefaulttimeout(3)

def initialise():
    global args
    # Argument Parser
    parser = argparse.ArgumentParser(
        description='[?] HostHunter ' + __version__ + ' - Help Page',
        epilog="Author: " + __author__)
    parser.add_argument(
        "-f",
        "--format",
        help="Choose between .CSV and .TXT output file formats.",
        default="csv")
    parser.add_argument(
        "-o",
        "--output",
        help="Sets the path of the output file.",
        type=str,
        default="vhosts")
    parser.add_argument(
        "-sc",
        "--screen-capture",
        help="Capture a screenshot of any associated Web Applications.",
        action="store_true",
        default=False)
    parser.add_argument("-t", "--target", help="Hunt a Single IP.")
    parser.add_argument(
        "targets",
        nargs='?',
        help="Sets the path of the target IPs file.",
        type=str,
        default="")
    parser.add_argument(
        "-V",
        "--version",
        help="Displays the current version.",
        action="store_true",
        default=False)
    parser.add_argument(
        "-d",
        "--debug",
        help="Displays additionla output and debugging information.",
        action="store_true",
        default=False)
    args = parser.parse_args()

    if len(sys.argv) < 2:
        print("\n[*] Error: No Arguments provided. ")
        print("Example Usage: python3 hosthunter.py -t 8.8.8.8 -o vhosts.csv")
        exit()

    if args.format.lower() != "txt" and args.format.lower() != "csv":
        print("\n[*] Error: File output format not supported. Choose between 'txt' or 'csv' .\n")
        print("Example Usage: python3 hosthunter.py targets.txt -f txt ")
        exit()

    if args.version:
        print("HostHunter version", __version__)
        print("Author:", __author__)
        exit()

    if args.target and args.targets:
        print(
            "\n[*] Error: Too many arguments! Either select single target or specify a list of targets.")
        print("Example Usage: python3 hosthunter.py -t 8.8.8.8 -o vhosts.csv")
        exit()
    # Targets Input File
    if args.targets and not os.path.exists(args.targets):
        print("\n[*] Error: targets file", args.targets, "does not exist.\n")
        exit()

    if os.path.exists(args.output):
        print(
            "\n[?] {} file already exists, would you like to overwrite it?".format(
                args.output))
        answer = input("Answer with [Y]es or [N]o : ").lower()
        if (answer == 'yes' or answer == 'y'):
            pass
        else:
            exit()


def read_targets():
    targets = []
    if args.target:
        targets.append(args.target)
    else:
        targets_fp = open(args.targets, "rt")  # Read File
        for target in targets_fp:
            targets.append(target)
        targets_fp.close()
    return targets


# Prints HostHunter Banner
def display_banner():
    banner = (
        "\n | $$  | $$                              | $$  | $$                                     \n"
        " | $$  | $$                      | $$    | $$  | $$                      | $$\n"
        " | $$  | $$  /$$$$$$   /$$$$$$$ /$$$$$$  | $$  | $$ /$$   /$$ /$$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$\n"
        " | $$$$$$$$ /$$__  $$ /$$_____/|_  $$_/  | $$$$$$$$| $$  | $$| $$__  $$|_  $$_/   /$$__  $$ /$$__  $$\n"
        " | $$__  $$| $$  \\ $$|  $$$$$$   | $$    | $$__  $$| $$  | $$| $$ \\ $$  | $$    | $$$$$$$$| $$  \\__/\n"
        " | $$  | $$| $$__| $$ \\____  $$  | $$ /$$| $$  | $$| $$__| $$| $$  | $$  | $$ /$$| $$_____/| $$\n"
        " | $$  | $$|  $$$$$$/ /$$$$$$$/  |  $$$$/| $$  | $$|  $$$$$$/| $$  | $$  |  $$$$/|  $$$$$$$| $$\n"
        " |__/  |__/ \\______/ |_______/    \\___/  |__/  |__/ \\______/ |__/  |__/   \\___/   \\_______/|__/  " +
        __version__ +
        "\n")

    print("%s" % banner)
    print("\n", "HostHunter: ", __version__)
    print(" Author : ", __author__)
    print("\n" + "|" + "-" * 100 + "|", end="\n\n")


class target:
    def __init__(self, address):
        self.address = address
        self.hname = []
        self.apps = []
        self.ipv6 = False

data_dict = {}

# Nessus Function  - Generates IP/Hostname pairs in Nessus tool format.
def nessus(hostx):
    nessus = open("nessus_"+args.output, 'a')
    for host in hostx.hname:
        row = host + "[" + hostx.address + "], "
        nessus.write(row)
    if not hostx.hname:
        nessus.write(hostx.address)
    nessus.close()
    return 0


# take_screenshot (Beta) Function - Takes screenshots of targets.
def take_screenshot(wpath, port):
    sleep(0.5)  # Delay

    if port == "80":
        url = "http://" + wpath
    else:
        url = "https://" + wpath + ":" + port

    try:
        driver.get(url)
        driver.save_screenshot(sc_path + "/" + wpath + "_" + port + ".png")
    except (urllib3.exceptions.ReadTimeoutError, requests.ConnectionError,
            urllib3.connection.ConnectionError,
            urllib3.exceptions.MaxRetryError,
            urllib3.exceptions.ConnectTimeoutError,
            urllib3.exceptions.TimeoutError,
            socket.error, socket.timeout):
        pass
    finally:
        driver.get('chrome://settings/clearBrowserData')
        driver.delete_all_cookies()  # Clear Cookies


# Validate Input Targets - Needs to be Replaced
def validate(hostx):
    if not checkers.is_ipv4(hostx.address):
        if checkers.is_ipv6(hostx.address):
            hostx.ipv6 = True
            return True
        else:
            print(
                "\n[*] \"",
                hostx.address,
                "\" is not a valid IPv4/IPv6 address and will be ignored.")
            return False
    else:
        return True


## sslGrabber - IPv6
def sslGrabber6(hostx,port):
    print(hostx.address)
    print (port)
    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(socket.socket(socket.AF_INET6), server_hostname=hostx.address)
    conn.connect((hostx.address, port))
    cert = conn.getpeercert()
    return cert['subjectAltName'][0][1]


# sslGrabber Function
def sslGrabber(hostx, port):
    try:
        cert = ssl.get_server_certificate((hostx.address, port))
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_hostname = x509.get_subject().CN
        # Get SAN
        alt_names = []
        for i in range(0, x509.get_extension_count()):
            ext = x509.get_extension(i)
            if "subjectAltName" in str(ext.get_short_name()):
                content = ext.__str__()
                for alt_name in content.split(","):
                    alt_names.append(alt_name.strip()[4:])

        # Add New HostNames to List
        if cert_hostname:
            for host in cert_hostname.split('\n'):
                if (host == "") or (host in hostx.hname):
                    pass
                else:
                    if args.debug == True:
                        print(host)
                    try:
                        host = host.replace('*.', '')
                    finally:
                        hostx.hname.append(host)
        for alt_name in alt_names:
            if (alt_name not in hostx.hname):
                hostx.hname.append(alt_name)
    except (urllib3.exceptions.ReadTimeoutError,
            requests.ConnectionError,
            urllib3.connection.ConnectionError,
            urllib3.exceptions.MaxRetryError,
            urllib3.exceptions.ConnectTimeoutError,
            urllib3.exceptions.TimeoutError,
            socket.error, socket.timeout):
        pass


# analyze_header Function
def analyze_header(header, hostx):
    try:
        r2 = requests.get("http://" + hostx.address,
                          allow_redirects=False,
                          headers=custom_headers, timeout=5).text
        r2.close()
        if (r2.status_code in range(300, 400)):
            try:
                webapp = (r2.headers['Location'])
                hostx.apps.append(webapp)
                hn = pattern_url.sub('', webapp)

                if hn not in hostx.hname:
                    hostx.hname.append(hn)
            except BaseException:
                return
    except BaseException:
        return


# queryAPI Function
def queryAPI(url, hostx):
    try:
        r2 = requests.get(url + hostx.address, custom_headers).text
        if (r2.find("No DNS A records found") == -
            1) and (r2.find("API count exceeded") == -
                    1 and r2.find("error") == -
                    1):
            for host in r2.split('\n'):
                if (host == "") or (host in hostx.hname):
                    pass
                else:
                    hostx.hname.append(host)
        # Add API count exceed detection
        else:
            pass
    except (requests.exceptions.ConnectionError,
            urllib3.connection.ConnectionError,
            urllib3.exceptions.ConnectTimeoutError,
            urllib3.exceptions.MaxRetryError,
            urllib3.exceptions.TimeoutError, socket.error, socket.timeout):
        print("\n[*] Error: connecting with HackerTarget.com API")
    finally:
        sleep(0.5)


def reverseiplookup(hostx):
    try:
        rhostname = socket.gethostbyaddr(hostx.address)[0]
    except socket.error:
        return
    if (rhostname not in hostx.hname):
        hostx.hname.append(rhostname)
    return


# Capture SIGINT
def sig_handler(signal, frame):
    print("\n[!] HostHunter is shutting down!")
    try:
        driver.close()
        driver.quit()
        signal.pause()
    except BaseException:
        pass
    print("\n[!] See you soon...\n")
    sys.exit(0)


# Write Function
def write_results():

    # Output File Naming & Path
    base_path = datetime.now().strftime("%d%m%Y_%H%M%S")
    appsf = open(args.output+base_path+".webapps", "wt")  # Write File
    vhostsf = open(args.output+base_path, "wt")

    if args.format.lower() == "csv":
        vhostsf.write(
            "\"" +
            "IP Address" +
            "\",\"" +
            "Port/Protocol" +
            "\",\"" +
            "Domains" +
            "\",\"" +
            "Operating System" +
            "\",\"" +
            "OS Version" +
            "\",\"" +
            "Notes" +
            "\"\n")  # vhosts.csv Header

    # Write Results in Nessus File
    #nessus(hostx)

    # Write Results in TXT File
    for item in data_dict:
        #print(data_dict[item].address)

        if args.format.lower() == 'txt':
            for hname in data_dict[item].hname:
                vhostsf.write(hname + "\n")

    # Write Results in CSV File
    if args.format.lower() == 'csv':
        # Merging the lists prooved Faster than list iterations
        hostnames = ','.join(hostx.hname)
        row = "\"" + hostx.address + "\"," + "\"443/tcp\"" + \
        "," + "\"" + hostnames + "\",\"\",\"\",\"\"" + "\n"
        vhostsf.write(row)

        if (hostx.apps):
            apps = ','.join(hostx.apps)
            row = "\"" + hostx.address
            + "\"," + "\"" + apps + "\"" + "\n"
            appsf.write(row)
    # Write Results in HTML File


# stats Function - Prints Statistics cause metrics are fun
def stats(start_time,counter,target_list):
    print("\n" + "|" + "-" * 100 + "|", end="\n\n")
    print("  Hunting Completed!", end="\n\n")
    print("  Searched against",len(target_list),"targets",end="\n\n")
    if counter == 0:
        print("  0 hostname was discovered in %s sec" %
              (round(time() - start_time, 2)), end="\n\n")
    else:
        print("  %s hostnames were discovered in %s sec" %
              (counter, round(time() - start_time, 2)), end="\n\n")
    print("|" + "-" * 100 + "|")


# Main Function
def main(argc, targets):
    counter = 0

    if args.debug == True:
        print("[!] Debug Mode: ON")

    for ip in targets:
        hostx = target(ip.replace("\n", ""))

        if validate(hostx):
            print("\n[+] Target: %s" % hostx.address)
        else:
            continue
        # Reverse DNS Lookup
        reverseiplookup(hostx)
    #    sslGrabber6(hostx,443)
    #    break
        # Fetch SSL Certificates [Ability to Add Custom SSL Certificates]
        sslGrabber(hostx, 21)
        sslGrabber(hostx, 25)
        sslGrabber(hostx, 443)
        sslGrabber(hostx, 8443)
        sslGrabber(hostx, 993)
        # Check 80/tcp over HTTP
        analyze_header("Location", hostx)

        # Querying HackerTarget.com API
        queryAPI("https://api.hackertarget.com/reverseiplookup/?q=", hostx)

        if hostx.hname:

            print("[+] Hostnames: ", end="\n")
            for item in hostx.hname:
                print(item)
                counter += 1

        else:
            print("[-] Hostnames: no results \n")
            continue

        if (hostx.apps):
            print("[+] Web Apps:")
            for url in hostx.apps:
                print(url)

        data_dict["hostx.address"] = hostx
        # END FOR LOOP
    # END IF

    write_results()
    return counter
# End of Main Function


# Main Module
if __name__ == "__main__":
    signal.signal(signal.SIGINT, sig_handler)  # Signal Listener
    start_time = time()  # Start Counter
    initialise()  # Input Argument Checks
    display_banner()  # Banner
    targets = read_targets()
    counter = main(sys.argv,targets)  # Main Function
    stats(start_time,counter,targets)
# EOF
