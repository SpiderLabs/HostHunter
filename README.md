HostHunter v1.0
======

A tool to efficiently discover and extract hostnames over a large set of target IP addresses. HostHunter utilises the HackerTarget API to enchance the results. It generates a vhosts.csv file containing the results of the reconnaissance.

======
## Installation

* Tested with Python 3.x.

### Linux
* Use wget command to download a latest Google Chrome debian package.  

```bash

$ wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb

$ dpkg -i ./google-chrome-stable_current_amd64.deb

$ sudo apt-get install -f
```

* Install python dependencies.
```bash
$ pip install -r requirements.txt
```


## Usage Example
```bash
$ python hosthunter.py <targets.txt>
```

```bash
$ cat vhosts.csv
```

## New Features
[X] Works with Python3  
[X] Scraps Bing.com results
[X] Supports .txt and .csv output file formats  
[X] Validate target IPv4 & IPv6 addresses  
[X] Supports IPv6 targets  
[X] Takes Screenshots  
[\_] Validate output hostnames  
[\_] BruteForce possible sub-domains  

## Notes
* Free APIs throttle the amount of requests per day per source IP address.
* HostHunter v2.0 is coming soon.


## Authors
* **Andreas Georgiou** - find me on twitter - [@mr_andreasgeo](https://twitter.com/Mr_AndreasGeo)
