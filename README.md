[![Python Version](https://img.shields.io/static/v1.svg?label=Python&message=3.x&color=blue)]()
[![GitHub release](https://img.shields.io/github/release/SpiderLabs/HostHunter.svg?color=orange&style=popout)](https://github.com/SpiderLabs/HostHunter/releases)
[![License](https://img.shields.io/github/license/spiderlabs/hosthunter.svg)](https://github.com/SpiderLabs/HostHunter/blob/master/LICENSE)
[![Issues](https://img.shields.io/github/issues/SpiderLabs/HostHunter?style=popout)](https://github.com/SpiderLabs/HostHunter/issues)
[![Twitter Follow](https://img.shields.io/twitter/follow/superhedgy.svg?style=social)](https://twitter.com/superhedgy)

HostHunter v2 (Beta)
======

A tool to efficiently discover and extract hostnames providing a large set of target IP addresses. HostHunter utilises simple OSINT techniques to map IP addresses with virtual hostnames. It generates a CSV or TXT file containing the results of the reconnaissance.

Latest version of HostHunter also takes screenshots of the target web applicatiinos. This functionality is currently in beta.

## Demo
<a href=https://asciinema.org/a/jp9B0IB6BzRAgbH3iNp7cCTpt><img src=https://asciinema.org/a/jp9B0IB6BzRAgbH3iNp7cCTpt.png alt=asciicast height=70% width=70%></a>

Click on the thumbnail above to view the demo.

## Installation
* Tested with Python 3.7.2.

### Linux / Mac OS
* Install python dependencies.
```bash
$ pip3 install -r requirements.txt
```

## Simple Usage Example
```bash
$ python3 hosthunter.py <targets.txt>
```

```bash
$ cat vhosts.csv
```

## More Examples
HostHunter Help Page
```bash
$ python3 ./hosthunter.py targets.txt -h
usage: hosthunter.py [-h] [-f FORMAT] [-o OUTPUT] [-sc] [-t TARGET] [-V] [targets]

[?] HostHunter v1.6 - Help Page

positional arguments:
  targets               Sets the path of the target IPs file.

optional arguments:
  -h, --help            show this help message and exit
  -f FORMAT, --format FORMAT
                        Choose between CSV and TXT output file formats.
  -o OUTPUT, --output OUTPUT
                        Sets the path of the output file.
  -sc, --screen-capture
                        Capture a screenshot of any associated Web Applications.
  -t TARGET, --target TARGET
                        Scan a Single IP.
  -V, --version         Displays the current version.

Author: Andreas Georgiou (@superhedgy)

```                        

Run HostHunter Screen Capture module and output a Nessus file:
```bash
$ python3 hosthunter.py <targets.txt> -sc -f csv -o hosts.csv
```
Display Results
```bash
$ cat hosts.csv
```
View Screenshots
```bash
$ open ./screen_captures/
```

## Features
- [x] Works with Python3  
- [x] Extracts information from SSL/TLS certificates.  
- [x] Supports Free HackerTarget API requests.  
- [x] Takes Screenshots of the target applications.  
- [x] Validates the targets IPv4 address.  
- [x] Supports .txt and .csv output file formats  
- [x] Gathers information from HTTP headers.
- [x] Verifies Internet access.
- [x] Retrieves hostname values from services at 21/tcp, 25/tcp, 80/tcp and 443/tcp ports.
- [x] Supports Nessus target format output.  

## Coming Next
- [ ] Improve output (IPs, HostNames, FQDNs)  
- [ ] Pause and Resume Execution   
- [ ] Support for a Premium HackerTarget API key   
- [ ] Support for IPv6   
- [ ] Gather information from additional APIs  
- [ ] Actively pull SSL certificates from other TCP ports  

## Notes
* Free APIs throttle the amount of requests per day per source IP address.

## License
This project is licensed under the MIT License.

## Authors
* **Andreas Georgiou** - follow me on twitter - [@superhedgy](https://twitter.com/superhedgy)

## StarGazers
Thank you for all the support & feedback!
[![Stargazers over time](https://starchart.cc/SpiderLabs/HostHunter.svg)](https://starchart.cc/SpiderLabs/HostHunter)
