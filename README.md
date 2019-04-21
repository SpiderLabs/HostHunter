HostHunter v1.5
======

A tool to efficiently discover and extract hostnames over a large set of target IP addresses. HostHunter utilises simple OSINT techniques. It generates a CSV file containing the results of the reconnaissance.

Taking screenshots was also added as a beta functionality.

## Demo
* Currently GitLab's markup language does not support HTML or CSS control over the images, thus the following link thumbnail is huge.

[![asciicast](https://asciinema.org/a/jp9B0IB6BzRAgbH3iNp7cCTpt.png)](https://asciinema.org/a/jp9B0IB6BzRAgbH3iNp7cCTpt)

## Installation
* Tested with Python 3.7.2.

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


## Simple Usage Example
```bash
$ python hosthunter.py <targets.txt>
```

```bash
$ cat vhosts.csv
```

## Full Functionality Example
```bash
$ python hosthunter.py <targets.txt> -o hosts.csv -f csv --bing -sc
```

```bash
$ cat hosts.csv
```

## Features
[X] Works with Python3  
[X] Scraps Bing.com results
[X] Supports .txt and .csv output file formats  
[X] Validate target IPv4 addresses  
[X] Takes Screenshots  
[X] Extracts hostnames from SSL certificates  
[X] Utilises Hacker Target API  

## Coming Next
[\_] Support HackerTarget API

## Notes
* Free APIs throttle the amount of requests per day per source IP address..

## License
This project is licensed under the MIT License.

## Authors
* **Andreas Georgiou** - find me on twitter - [@superhedgy](https://twitter.com/superhedgy)
