![Python Version](https://img.shields.io/static/v1.svg?label=Python&message=3.x&color=Blue)
![Twitter Follow](https://img.shields.io/twitter/follow/superhedgy.svg?label=Follow&style=social)

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
$ python3 hosthunter.py <targets.txt>
```

```bash
$ cat vhosts.csv
```

## More Examples
HostHunter Help Page
```bash
$ python3 hosthunter.py -h
usage: hosthunter.py [-h] [-V] [-f FORMAT] [-o OUTPUT] [-b] [-sc] targets

|<--- HostHunter v1.5 - Help Page --->|

positional arguments:
  targets               Sets the path of the target IPs file.

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         Displays the currenct version.
  -f FORMAT, --format FORMAT
                        Choose between CSV and TXT output file formats.
  -o OUTPUT, --output OUTPUT
                        Sets the path of the output file.
  -b, --bing            Use Bing.com search engine to discover more hostnames
                        associated with the target IP addreses.
  -sc, --screen-capture
                        Capture a screen shot of any associated Web
                        Applications.
```                        

Run HostHunter with Bing and Screen Captures modules enabled
```bash
$ python3 hosthunter.py <targets.txt> --bing -sc -f csv -o hosts.csv
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
[X] Works with Python3  
[X] Scraps Bing.com results  
[X] Supports .txt and .csv output file formats  
[X] Validates target IPv4 addresses  
[X] Takes Screenshots of the targets
[X] Extracts hostnames from SSL certificates  
[X] Utilises Hacker Target API  

## Coming Next
[\_] Support for HackerTarget API key

## Notes
* Free APIs throttle the amount of requests per day per source IP address.

## License
This project is licensed under the MIT License.

## Authors
* **Andreas Georgiou** - find me on twitter - [@superhedgy](https://twitter.com/superhedgy)
