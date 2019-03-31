#!/usr/bin/env python3

import os
import time
import requests
import argparse
import subprocess as subp
from xml.etree import ElementTree

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
version = '1.0.1'

parser = argparse.ArgumentParser(description="Manipulate Chromecast Devices in your Network")
parser.add_argument('-t', '--ip', help='IP Address of Chromecast', required=True)
args = parser.parse_args()
ip = args.ip

port = '8008'
header = {'Content-Type' : 'application/json'}

def banner():
	os.system('clear')
	text = r'''
    __    _  __ __                    __
   / /__ (_)/ // /_____ ____ _ _____ / /_
  / //_// // // // ___// __ `// ___// __/
 / ,<  / // // // /__ / /_/ /(__  )/ /_
/_/|_|/_//_//_/ \___/ \__,_//____/ \__/'''

	print (G + text + W + '\n')
	print (G + '[>]' + C + ' Created By : ' + W + 'thewhiteh4t')
	print (G + '[>]' + C + ' Version    : ' + W + version + '\n')


def updater():
	print (G + '[+]' + C + ' Checking For Updates...' + W, end='')
	update = requests.get('https://raw.githubusercontent.com/thewhiteh4t/killcast/master/version.txt', timeout = 5)
	update = update.text.split(' ')[1]
	update = update.strip()

	if update != version:
		print ('\n\n' + G + '[!]' + C + ' A New Version is Available : ' + W + update)
		ans = input('\n' + G + '[!]' + C + ' Update ? [y/n] : ' + W)
		if ans == 'y':
			print ('\n' + G + '[+]' + C + ' Updating...' + W + '\n')
			subp.check_output(['git', 'reset', '--hard', 'origin/master'])
			subp.check_output(['git', 'pull'])
			print ('\n' + G + '[+]' + C + ' Script Updated...Execute Again...' + W)
			sys.exit()
		elif ans == 'n':
			pass
		else:
			print ('\n' + R + '[-]' + C + ' Invalid Character...Skipping...'+ W)
	else:
		print (G + ' Up-to-date' + W)
	print ('\n', end='')

def info():
	global ip, header
	info_url = 'http://{}:{}/ssdp/device-desc.xml'.format(ip,port)
	info2_url = 'http://{}:{}/setup/eureka_info'.format(ip, port)
	try:
		info = requests.get(info_url, headers=header)
		root = ElementTree.fromstring(info.text)
		rtag = root.tag.strip('root')
		rtag = rtag.strip('{}')
		ns = {'ns' : '{}'.format(rtag)}
		name = root.findall('.//ns:friendlyName', namespaces=ns)
		manf = root.findall('.//ns:manufacturer', namespaces=ns)
		model = root.findall('.//ns:modelName', namespaces=ns)
		name = name[0].text
		manf = manf[0].text
		model = model[0].text
		print (G + '[+]' + C + ' Target IP      : ' + W + ip + '\n')
		print (G + '[+]' + C + ' Name           : ' + W + name)
		print (G + '[+]' + C + ' Manufacturer   : ' + W + manf)
		print (G + '[+]' + C + ' Model Name     : ' + W + model)

		info2 = requests.get(info2_url, headers=header)
		infjson = info2.json()
		bssid = infjson['bssid']
		bver = infjson['build_version']
		brev = infjson['cast_build_revision']
		eth = infjson['ethernet_connected']
		locale = infjson['locale']
		ccode = infjson['location']['country_code']
		nlevel = infjson['noise_level']
		ssid = infjson['ssid']
		tzone = infjson['timezone']
		uptime = infjson['uptime']
		print (G + '[+]' + C + ' BSSID          : ' + W + str(bssid))
		print (G + '[+]' + C + ' Build Version  : ' + W + str(bver))
		print (G + '[+]' + C + ' Build Revision : ' + W + str(brev))
		print (G + '[+]' + C + ' Ethernet Conn. : ' + W + str(eth))
		print (G + '[+]' + C + ' Locale         : ' + W + str(locale))
		print (G + '[+]' + C + ' Country Code   : ' + W + str(ccode))
		print (G + '[+]' + C + ' Noise Level    : ' + W + str(nlevel))
		print (G + '[+]' + C + ' SSID           : ' + W + str(ssid))
		print (G + '[+]' + C + ' Timezone       : ' + W + str(tzone))
		print (G + '[+]' + C + ' Uptime         : ' + W + str(uptime))
		print ('\n', end='')
	except:
		pass

def rename():
	global ip, port, header
	print ('\n', end='')
	newname = input(G + '[+]' + C + ' Enter New Name : ' + W)
	url = 'http://{}:{}/setup/set_eureka_info'.format(ip, port)
	data = {'name' : '{}'.format(newname)}
	print (G + '[+]' + C + ' Changing Name...' + W)
	r = requests.post(url, json=data, headers=header)
	print ('\n', end='')

def reboot():
	global ip, port, header
	print ('\n', end='')
	url = 'http://{}:{}/setup/reboot'.format(ip,port)
	data = {'params' : 'now'}
	print (G + '[+]' + C + ' Rebooting...')
	r = requests.post(url, json=data, headers=header)
	print ('\n', end='')

def reset():
	global ip, port, header
	print ('\n', end='')
	reset = 'http://{}:{}/setup/reboot'.format(ip, port)
	data = {'params' : 'fdr'}
	print (G + '[+]' + C + ' Performing Factory Reset...')
	r = requests.post(reset, json=data, headers=header)
	print ('\n', end='')

def appkill():
	global ip, port, header
	print ('\n', end='')
	print (G + '[1]' + C + ' YouTube' + W)
	print (G + '[2]' + C + ' Netflix' + W)
	#print (G + '[3]' + C + ' Google Play Music' + W)
	choice = input('\n' + R + '[>] ' + W)
	if choice == '1':
		print (G + '[+]' + C + ' Killing YouTube...')
		url = 'http://{}:{}/apps/YouTube'.format(ip, port)
		r = requests.delete(url, headers=header)
		print ('\n', end='')
	elif choice == '2':
		print (G + '[+]' + C + ' Killing Netflix...')
		url = 'http://{}:{}/apps/Netflix'.format(ip, port)
		r = requests.delete(url, headers=header)
		print ('\n', end='')
	elif choice == '3':
		print (G + '[+]' + C + ' Killing Google Play Music...')
		url = 'http://{}:{}/apps/GoogleMusic'.format(ip, port)
		r = requests.delete(url, headers=header)
		print ('\n', end='')
	print ('\n', end='')

def core():
	while True:
		print (G + '[*]' + C + ' Actions : ' + W + '\n')
		print (G + '[1]' + C + ' Info' + W)
		print (G + '[2]' + C + ' Rename' + W)
		print (G + '[3]' + C + ' Reboot' + W)
		print (G + '[4]' + C + ' Kill Apps' + W)
		print (G + '[5]' + C + ' Factory Reset' + W)
		print (G + '[6]' + C + ' Exit' + W)

		choice = input('\n' + R + '[>] ' + W)

		if choice == '1':
			info()
		elif choice == '2':
			rename()
		elif choice == '3':
			reboot()
		elif choice == '4':
			appkill()
		elif choice == '5':
			reset()
		elif choice == '6':
			exit()
		else:
			print (R + '[-]' + C + ' Invalid Choice...Try Again.' + W)
			print ('\n', end='')
			core()

try:
	banner()
	updater()
	info()
	core()
except KeyboardInterrupt:
	print ('\n' + R + '[-]' + C + 'Keyboard Interrupt.' + W)
