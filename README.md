# Starts wireshark for pod on kubernetes reachable via teleport

## Installation
pip3 install git+https://github.com/mogaika/georgeJ.git

## Usage
```
usage: georgeJ [-h] [-h] [--pod POD] [--interface INTERFACE] [-tsh]

optional arguments:
  -h, --help            show this help message and exit
  --pod POD             regex for filtering pods (default .*)
  --interface INTERFACE
                        regex for interface or use "any" (default any)
  -tsh                  use tsh way
```
