# Starts wireshark for pod on kubernetes reachable via teleport

## unmaintained copy and have fun 

## Installation
pip3.7 install --user -r requirements.txt

## Usage
```
usage: georgeJ [-h] [--pod POD] [--container CONTAINER]
               [--interface INTERFACE]

optional arguments:
  -h, --help            show this help message and exit
  --pod POD             regex for filtering pods (default .*)
  --container CONTAINER regex for filtering containers (default .*)
  --interface INTERFACE regex for filtering interfaces (default .*)
```
