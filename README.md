<p align="center"><img src="https://i.imgur.com/HuRoaZn.png"></p>
<h4 align="center">
Manipulate Chromecast Devices in your Network
</h4>

<p align="center">
<img src="https://img.shields.io/badge/Python-3-brightgreen.svg?style=plastic">
<img src="https://img.shields.io/badge/Termux-✔-red.svg?style=plastic">
</p>

<p align="center">
  <br>
  Available in
  <br>
  <img src="https://i.imgur.com/IPiAUZi.png">
</p>

<p align="center"><img src="https://i.imgur.com/8EOXyxX.png"></p>

Inspiration - [Thousands of Google Chromecast Devices Hijacked to Promote PewDiePie](https://thehackernews.com/2019/01/chromecast-pewdiepie-hack.html)

**This tool is a Proof of Concept and is for Research Purposes Only, killcast shows how Chromecast devices can be easily manipulated and hijacked by anyone.**

## Features

* Extract Interesting Information such as Build Version, Country, Timezone etc
* Rename
* Reboot
* Perform Factory Reset
* Kill Active Applications such as YouTube, Netflix and Google Play Music

## What is not working

* Play any YouTube Video
* Unable to kill Play Music
* Other things that we are not aware of ;)

## Tested On :

* Kali Linux 2019.1
* Ubuntu 18.04
* Termux

## Installation

### Ubuntu / Kali Linux / Termux

```
git clone https://github.com/thewhiteh4t/killcast.git
cd killcast
apt-get install python3
pip install requests
```

## Usage

```
python3 killcast.py -h

usage: killcast.py [-h] -t IP

Manipulate Chromecast Devices in your Network

optional arguments:
  -h, --help      show this help message and exit
  -t IP, --ip IP  IP Address of Chromecast
```

```
python3 killcast.py -t 192.168.0.100
```

## Demo - [YouTube](https://youtu.be/8wmWnMVE2aw)
