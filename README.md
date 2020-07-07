<p align="center"><img src="https://i.imgur.com/k9L3q2x.jpg"></p>
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
  <img src="https://i.imgur.com/1wJVDV5.png">
</p>

Inspiration - [Thousands of Google Chromecast Devices Hijacked to Promote PewDiePie](https://thehackernews.com/2019/01/chromecast-pewdiepie-hack.html)

**This tool is a Proof of Concept and is for Research Purposes Only, killcast shows how Chromecast devices can be easily manipulated and hijacked by anyone.**

## Features

* Extract Chromecast Device Information
* IP Address Reconnaissance
* Extract Saved Networks
* Scan for Nearby WiFi Access Points
* Forget a WiFi Access Point
* Rename Device
* Kill Running Applications
* Reboot Device
* Perform Factory Reset

## To Do

* Play YouTube Videos
* Set wallpapers
* Kill more applications

## Tested On :

* BlackArch Linux
* Kali Linux
* Ubuntu
* Termux

## Installation

### BlackArch
```
pacman -S killcast
```

### Ubuntu / Kali Linux / Termux

```
git clone https://github.com/thewhiteh4t/killcast.git
cd killcast
pip3 install requests
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

## Demo

| Demo | Link |
|-|-|
| First Version | https://www.youtube.com/watch?v=8wmWnMVE2aw |