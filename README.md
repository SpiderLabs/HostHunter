HostHunter v1.5
======

A tool to efficiently discover and extract hostnames over a large set of target IP addresses. HostHunter utilises the HackerTarget API to enchance the results. It generates a vhosts.csv file containing the results of the reconnaissance.


## Installation

* Tested with Python 3.x.

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
[x] Works with Python3  
[x] Scraps Bing.com for results  
[ ] Supports .txt and .csv output file formats.  
[ ] Validate target IPv4 & IPv6 addresses.  
[ ] Supports IPv6 targets.  
[ ] Validate output hostnames.  
[ ] BruteForce possible sub-domains.  
[ ] Remove duplicates.  

## Notes

* Free APIs throttle the amount of requests per day per source IP address.
* HostHunter v2.0 is coming soon.


## Authors
* **Andreas Georgiou** - find me on twitter - [@mr_andreasgeo](https://twitter.com/Mr_AndreasGeo)

