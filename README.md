# Capture HTTP Authetication

Capture and log Authorization HTTP header field containing apache credentials for user authentication.

## Requirements

- [scapy](https://pypi.org/project/scapy/)

## Usage
```
usage: sniff_auth.py [-h] [-l LOG_LEVEL] -i INTERFACE

Capture HTTP Authorization Header field

optional arguments:
  -h, --help            show this help message and exit
  -l LOG_LEVEL, --log_level LOG_LEVEL
                        minimum Log level (default: INFO)
  -i INTERFACE, --interface INTERFACE
                        target capture interface (default: None)
```