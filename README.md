HostHunter v1.0
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
[x] Scraps Bing.com results  
[x] Supports .txt and .csv output file formats.  
[x] Validate target IPv4 & IPv6 addresses.  
[x] Supports IPv6 targets.  
[\_] Validate output hostnames.  
[\_] BruteForce possible sub-domains.  
[x] Remove duplicates
[x] Takes Screenshots
[\_] Store output in a SQL DB  

## Notes

* Free APIs throttle the amount of requests per day per source IP address.
* HostHunter v2.0 is coming soon.


## Authors
* **Andreas Georgiou** - find me on twitter - [@mr_andreasgeo](https://twitter.com/Mr_AndreasGeo)
