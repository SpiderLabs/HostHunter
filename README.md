HostHunter
======

A tool to efficiently discover and extract hostnames over a large set of target IP addresses. HostHunter utilises the HackerTarget API to enchance the results. It generates a vhosts.csv file containing the results of the reconnaissance.


## Installation

* Tested with Python 2.7.x.

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


## Notes

* Free APIs throttle the amount of requests per day per source IP address.


## Authors
* **Andreas Georgiou** - find me on twitter - [@mr_andreasgeo](https://twitter.com/Mr_AndreasGeo)

