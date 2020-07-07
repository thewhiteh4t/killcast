#!/usr/bin/env python3

import os
import sys
import json
import time
import socket
import requests
import argparse
import ipaddress
from xml.etree import ElementTree
requests.packages.urllib3.disable_warnings()

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

version = '1.0.3'

parser = argparse.ArgumentParser(description="Manipulate Chromecast Devices in your Network")
parser.add_argument('-t', '--ip', help='IP Address of Chromecast', required=True)
args = parser.parse_args()
ip = args.ip

priv_ip = False

if ipaddress.ip_address(ip).is_private:
	priv_ip = True
else:
	pass

http_port = '8008'
https_port = '8443'
http_header = {'Content-Type' : 'application/json'}
https_header = {'Content-Type' : 'application/json', 'Authorization': 'kill.cast'}

def banner():
	text = r'''
    __    _  __ __                    __
   / /__ (_)/ // /_____ ____ _ _____ / /_
  / //_// // // // ___// __ `// ___// __/
 / ,<  / // // // /__ / /_/ /(__  )/ /_
/_/|_|/_//_//_/ \___/ \__,_//____/ \__/'''

	print(G + text + W + '\n')
	print(G + '[>]' + C + ' Created By : ' + W + 'thewhiteh4t')
	print(G + ' |---> ' + C + 'Twitter : ' + W + 'https://twitter.com/thewhiteh4t')
	print(G + ' |---> ' + C + 'Discord : ' + W + 'https://discord.com/invite/A2FUvkM')
	print(G + '[>]' + C + ' Version    : ' + W + version + '\n')

def ver_check():
	print(G + '[+]' + C + ' Checking for Updates...', end='')
	ver_url = 'https://raw.githubusercontent.com/thewhiteh4t/killcast/master/version.txt'
	try:
		ver_rqst = requests.get(ver_url, timeout=5)
		ver_sc = ver_rqst.status_code
		if ver_sc == 200:
			github_ver = ver_rqst.text
			github_ver = github_ver.strip()
			if version == github_ver:
				print(C + '[' + G + ' Up-To-Date ' + C +']' + '\n')
			else:
				print(C + '[' + G + ' Available : {} '.format(github_ver) + C + ']' + '\n')
		else:
			print(C + '[' + R + ' Status : {} '.format(ver_sc) + C + ']' + '\n')
	except Exception as e:
		print('\n\n' + R + '[-]' + C + ' Exception : ' + W + str(e))

def conn_test():
	http_test = False
	https_test = False
	print('\n' + Y + '[!] Testing Connection...' + W + '\n')
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.settimeout(5)
		try:
			s.connect((ip, int(http_port)))
			http_test = True
		except OSError:
			print(R + '[-]' + C + ' Exception : ' + W + 'Cannot Connect to Port 8008')
	
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.settimeout(5)
		try:
			s.connect((ip, int(https_port)))
			https_test = True
		except OSError:
			print(R + '[-]' + C + ' Exception : ' + W + 'Cannot Connect to Port 8443')

	if http_test == False or https_test == False:
		print(R + '[-]' + C + ' Connection Test Failed' + W)
		sys.exit()
	else:
		print(G + '[+]' + C + ' Connection Test Passed' + W)

def info():
	print('\n' + Y + '[!] Getting Device Information...' + W + '\n')
	dev_url = 'http://{}:{}/ssdp/device-desc.xml'.format(ip, http_port)
	eur_url = 'http://{}:{}/setup/eureka_info'.format(ip, http_port)
	try:
		dev_rqst = requests.get(dev_url, headers=http_header, timeout=10)
		dev_sc = dev_rqst.status_code
		if dev_sc == 200:
			root = ElementTree.fromstring(dev_rqst.text)
			rtag = root.tag.strip('root')
			rtag = rtag.strip('{}')
			ns = {'ns' : '{}'.format(rtag)}
			name = root.findall('.//ns:friendlyName', namespaces=ns)
			manf = root.findall('.//ns:manufacturer', namespaces=ns)
			model = root.findall('.//ns:modelName', namespaces=ns)
			name = name[0].text
			manf = manf[0].text
			model = model[0].text
			print (G + '[+]' + C + ' Name : ' + W + name)
			print (G + '[+]' + C + ' Manufacturer : ' + W + manf)
			print (G + '[+]' + C + ' Model Name : ' + W + model)
		else:
			print(R + '[-]' + C + ' Failed, Status : ' + W + str(dev_sc))
			sys.exit()

		eur_rqst = requests.get(eur_url, headers=http_header, timeout=10)
		eur_sc = eur_rqst.status_code
		key_list = [
			'bssid', 'build_version',
			'cast_build_revision', 'ethernet_connected',
			'locale', 'mac_address',
			'noise_level', 'signal_level',
			'ssid', 'timezone',
			'uptime', 'wpa_configured'
		]

		if eur_sc == 200:
			infjson = eur_rqst.json()
			for key, value in infjson.items():
				if key in key_list:
					key = key.replace('_', ' ').title()
					if value == '':
						value = 'Not Available'
					else:
						pass
					print(G + '[+]' + C + ' {} : '.format(key) + W + str(value))
				else:
					pass
		else:
			print(R + '[-]' + C + ' Failed, Status : ' + W + str(eur_sc))
			sys.exit()
	except Exception as exc:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))

def iprecon():
	if priv_ip == True:
		print('\n' + R + '[-]' + C + ' Private IP Address, Skipping...' + W)
		return
	else:
		pass
	print('\n' + Y + '[!] Getting IP Information...' + W + '\n')
	key_list = ['country', 'city', 'isp', 'org', 'as']
	service = 'http://ip-api.com/json/'
	serv_url =  service + ip
	try:
		r = requests.get(serv_url, timeout=5)
		r_sc = r.status_code
		if r_sc == 200:
			r_data = r.text
			json_data = json.loads(r_data)
			for key, value in json_data.items():
				if key in key_list:
					key = key.title()
					print(G + '[+]' + C + ' {} : '.format(key) + W + str(value))
		else:
			print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))
	except Exception as exc:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))

def saved_net():
	print('\n' + Y + '[!] Sending Request...' + W)
	url = 'https://{}:{}/setup/configured_networks'.format(ip, https_port)
	try:
		r = requests.get(url, headers=https_header, timeout=10, verify=False)
	except Exception as exc:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))
		return
	r_sc = r.status_code
	if r_sc == 200:
		r_data = r.text
		json_data = json.loads(r_data)
		for entry in json_data:
			print()
			for key, value in entry.items():
				key = key.replace('_', ' ').title()
				print(G + '[+]' + C + ' {} : '.format(key) + W + str(value))
	else:
		print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))

def wscan():
	print('\n' + Y + '[!] Sending Request...' + W)
	scan_url = 'https://{}:{}/setup/scan_wifi'.format(ip, https_port)
	result_url = 'https://{}:{}/setup/scan_results'.format(ip, https_port)
	try:
		scan_r = requests.post(scan_url, headers=https_header, timeout=10, verify=False)
	except Exception as exc:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))
		return
	scan_sc = scan_r.status_code
	if scan_sc == 200:
		print(G + '[+]' + C + ' Action Completed!' + W)
	else:
		print(R + '[-]' + C + ' Failed, Status : ' + W + str(scan_sc))
	print(Y + '[!] Getting Scan Results...' + W)
	key_list = ['bssid', 'signal_level', 'ssid']
	try:
		result_r = requests.get(result_url, headers=https_header, timeout=10, verify=False)
	except Exception as exc:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))
		return
	result_sc = result_r.status_code
	if result_sc == 200:
		result_data = result_r.text
		result_json = json.loads(result_data)
		for entry in result_json:
			print()
			for key, value in entry.items():
				if key in key_list:
					key = key.replace('_', ' ').title()
					print(G + '[+]' + C + ' {} : '.format(key) + W + str(value))
	else:
		print(R + '[-]' + C + ' Failed, Status : ' + W + str(result_sc))

def wforget():
	choice = input('\n' + G + '[+]' + C + ' WPA ID : ' + W)
	url = 'https://{}:{}/setup/forget_wifi'.format(ip, https_port)
	data = {"wpa_id": int(choice)}
	print('\n' + Y + '[!] Sending Request...' + W)
	try:
		r = requests.post(url, json=data, headers=https_header, timeout=10, verify=False)
	except Exception as exc:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))
		return
	r_sc = r.status_code
	if r_sc == 200:
		print(G + '[+]' + C + ' Action Completed!' + W)
	else:
		print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))

def rename():
	newname = input('\n' + G + '[+]' + C + ' New Name : ' + W)
	url = 'https://{}:{}/setup/set_eureka_info'.format(ip, https_port)
	data = {'name' : '{}'.format(newname)}
	print(Y + '[!] Sending Request...' + W)
	try:
		r = requests.post(url, json=data, headers=https_header, timeout=10, verify=False)
	except Exception as exc:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))
		return
	r_sc = r.status_code
	if r_sc == 200:
		print(G + '[+]' + C + ' Action Completed!' + W)
	else:
		print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))

def reboot():
	print ('\n' + Y + '[!] Sending Request...' + W)
	url = 'https://{}:{}/setup/reboot'.format(ip, https_port)
	data = {'params' : 'now'}
	try:
		r = requests.post(url, json=data, headers=https_header, verify=False)
	except Exception as e:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))
		return
	r_sc = r.status_code
	if r_sc == 200:
		print(G + '[+]' + C + ' Action Completed!' + W)
	else:
		print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))

def reset():
	print ('\n' + Y + '[!] Sending Request...' + W)
	reset = 'https://{}:{}/setup/reboot'.format(ip, https_port)
	data = {'params' : 'fdr'}
	try:
		r = requests.post(reset, json=data, headers=https_header, verify=False)
	except Exception as exc:
		print(R + '[-]' + C + ' Exception : ' + W + str(exc))
		return
	r_sc = r.status_code
	if r_sc == 200:
		print(G + '[+]' + C + ' Action Completed!' + W)
	else:
		print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))

def appkill():
	print (G + '[1]' + C + ' YouTube' + W)
	print (G + '[2]' + C + ' Netflix' + W)
	#print (G + '[3]' + C + ' Google Play Music' + W)
	choice = input('\n' + R + '[>] ' + W)
	print ('\n' + Y + '[!] Sending Request...' + W)
	if choice == '1':
		url = 'http://{}:{}/apps/YouTube'.format(ip, http_port)
		try:
			r = requests.delete(url, headers=http_header, verify=False)
		except Exception as exc:
			print(R + '[-]' + C + ' Exception : ' + W + str(exc))
			return
		r_sc = r.status_code
		if r_sc == 200:
			print(G + '[+]' + C + ' Action Completed!' + W)
		else:
			print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))
	elif choice == '2':
		url = 'http://{}:{}/apps/Netflix'.format(ip, http_port)
		try:
			r = requests.delete(url, headers=http_header, verify=False)
		except Exception as exc:
			print(R + '[-]' + C + ' Exception : ' + W + str(exc))
			return
		r_sc = r.status_code
		if r_sc == 200:
			print(G + '[+]' + C + ' Action Completed!' + W)
		else:
			print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))
	#elif choice == '3':
	#	print (G + '[+]' + C + ' Killing Google Play Music...')
	#	url = 'http://{}:{}/apps/GoogleMusic'.format(ip, http_port)
	#	r = requests.delete(url, headers=header, verify=False)
	#	r_sc = r.status_code
	#	if r_sc == 200:
	#		print(G + '[+]' + C + ' Action Completed!' + W)
	#	else:
	#		print(R + '[-]' + C + ' Failed, Status : ' + W + str(r_sc))

def menu():
	while True:
		print('\n' + Y + '[!] Actions : ' + W + '\n')
		print(G + '[1]' + C + ' Device Information' + W)
		print(G + '[2]' + C + ' IP Information' + W)
		print(G + '[3]' + C + ' Saved Networks' + W)
		print(G + '[4]' + C + ' Scan for Networks' + W)
		print(G + '[5]' + C + ' Forget WiFi Network' + W)
		print(G + '[6]' + C + ' Rename' + W)
		print(G + '[7]' + C + ' Kill Apps' + W)
		print(G + '[8]' + C + ' Reboot' + W)
		print(G + '[9]' + C + ' Factory Reset' + W)
		print(G + '[0]' + C + ' Exit' + W)

		choice = input('\n' + R + '[>] ' + W)

		if choice == '1':
			info()
		elif choice == '2':
			iprecon()
		elif choice == '3':
			saved_net()
		elif choice == '4':
			wscan()
		elif choice == '5':
			wforget()
		elif choice == '6':
			rename()
		elif choice == '7':
			appkill()
		elif choice == '8':
			reboot()
		elif choice == '9':
			reset()
		elif choice == '0':
			sys.exit()
		else:
			print ('\n' + R + '[-]' + C + ' Invalid Choice...Try Again.' + W)
			menu()

try:
	banner()
	ver_check()
	print (G + '[+]' + C + ' Target IP : ' + W + ip)
	conn_test()
	info()
	iprecon()
	menu()
except KeyboardInterrupt:
	print ('\n' + R + '[-]' + C + 'Keyboard Interrupt.' + W)
	sys.exit()