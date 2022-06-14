import sys
import argparse
from my_print import *
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPCursorError, LDAPBindError

class LdapSearch:
	def __init__(self, domain, dc_ip, username='', password=''):
		self.domain = domain
		self.dc_ip = dc_ip

		self.server = None
		self.conn = None
		self.search_b = ''

		self.username = username
		self.password = password

		self.res = []
		self.account = {}


	def dns2ldap(self, domain):
		self.search_b = 'DC=' + ',DC='.join(self.domain.split('.'))

	def init_server(self):
		self.server = Server(self.dc_ip, get_info=ALL)

	def init_connection(self):
		if(self.server is not None):
			if(self.username != '' and self.password != ''):
				try:
					self.conn = Connection(self.server, user=f'{self.domain}\\{self.username}', password=self.password, authentication=NTLM, auto_bind=True)

					### Verifying account by requesting domain controllers ###
					self.exec('dc', quiet=True)
					if(len(self.res) > 0):
						success(f'Account valid: {self.domain}\\{self.username}:{self.password}')
						self.account[self.username] = self.password
					else:
						raise LDAPBindError

				except LDAPBindError:
					warn(f'Auth failed for: {self.username}:{self.password}')

			else:
				log("Performing anonymous query")
				self.conn = Connection(self.server, auto_bind=True)
		else:
			warn('No server initialized')

	def init_all(self):
		self.init_server()
		self.dns2ldap(self.domain)
		self.init_connection()

	def add_account(self, username, password):
		self.username = username
		self.password = password
		self.init_connection()

	def flush_res(self):
		self.res = []

	def exec(self, action, quiet=False):
		self.flush_res()
		to_look = action.lower() if(action.lower() in ['da', 'desc', 'users', 'all_desc', 'computers', 'dc', 'mssql', 'exchange']) else None
		if(to_look is None):
			warn("Unknown action :(")
			return 0

		if(self.conn is None):
			warn('Couln\'t connect to the server Ldap')
			return 0
			
		if(to_look == 'da'):
			self.conn.search(self.search_b, '(objectclass=person)', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			for e in self.conn.entries:
				try:
					attr_group = str(e.memberof)
					name = str(e.samAccountName)
					if('domain' in attr_group.lower() and 'adm' in attr_group.lower()):
						self.res.append(name)
				except:
					pass

		elif(to_look == 'dc'):
			self.conn.search(self.search_b, '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			for e in self.conn.entries:
				try:
					name = str(e.samAccountName)
					self.res.append(name)
				
				except:
					pass

		elif(to_look == "mssql"):
			self.conn.search(self.search_b, '(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			for e in self.conn.entries:
				try:
					name = str(e.samAccountName)
					self.res.append(name.rstrip('$'))
				
				except:
					pass


		elif(to_look == 'users'):
			self.conn.search(self.search_b, '(&(objectClass=user)(objectCategory=Person))', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			for e in self.conn.entries:
				try:
					name = str(e.samAccountName)
					self.res.append(name)
				
				except:
					pass
		elif(to_look == 'all_desc'):
			self.conn.search(self.search_b, '(|(objectCategory=person)(objectCategory=computer))', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			for e in self.conn.entries:
				try:
					desc = str(e.description)
					name = str(e.samAccountName)
					self.res.append(f'{name:25} ==> {desc}')
				except:
					pass

		elif(to_look == 'computers'):
			self.conn.search(self.search_b, '(objectCategory=computer)', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			for e in self.conn.entries:
				try:
					name = str(e.samAccountName)
					self.res.append(name.rstrip('$'))
				except:
					pass

		elif(to_look == 'exchange'):
			self.conn.search(self.search_b, '(&(objectCategory=computer)(servicePrincipalName=exchangeMDB*)(operatingSystem=Windows Server*))', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			for e in self.conn.entries:
				try:
					name = str(e.samAccountName)
					self.res.append(name.rstrip('$'))
				except:
					pass

		else:
			self.conn.search(self.search_b, '(|(objectCategory=person)(objectCategory=computer))', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
			for e in self.conn.entries:
				try:
					desc = str(e.description)
					name = str(e.samAccountName)
					if('pw' in desc.lower() or 'pass' in desc.lower() or '=' in desc.lower()):
						self.res.append(f'{name:25} ==> {desc}')

				except:
					pass

		if(len(self.res) != 0):
			if(not(quiet)):
				success('Query executed with success')
				for e in self.res:
					log(e)
				save_it = input('Save result to file ? (Y/N) ')
				if(save_it.upper() == 'Y'):
					filename = input('Filename: ')
					with open(filename, 'w') as f:
						for r in self.res:
							f.write(r + '\n')
					success(f'Result saved in {filename}')

		else:
			if(not(quiet)):
				warn('No result from query')


if __name__ == '__main__':
	parser = argparse.ArgumentParser(add_help = True, description = "Ldap search info utilitaire")
	parser.add_argument('-domain-name', action='store', metavar = "DOMAIN name", help='Hostname of the domain controller to use')
	parser.add_argument('-dc-ip', action='store', metavar = "DC Ip", help='Ip of the domain controller to use')
	parser.add_argument('-u', action='store', metavar='username', help='username to use for auth')
	parser.add_argument('-p', action='store', metavar='password', help='passord to use for auth')
	parser.add_argument('-a', action='store', metavar='action', help='Action to perform:\n\t- search da (-a DA)\n\t- search users (-a users)\n\t- search description (-a desc)\n\t- search all description (-a all_desc)')

	options = parser.parse_args()

	if(len(sys.argv) == 1):
		warn('No arguments specified..')
		exit(0)

	domain, dc_ip, action = options.domain_name, options.dc_ip, options.a
	if(domain == None or dc_ip == None or action == None):
		warn(f'Domain name / ip  and action should be specified:\n\t- python3 {sys.argv[0]} -dc-host <host> -dc-ip <ip> -a <action>')
		exit(0)

	username = options.u if(options.u != None) else ''
	password = options.p if(options.p != None) else ''


	if(action is None):
		warn(f"Unknow action {action}")
		exit(0)
	else:
		to_exec = action.lower()


	ldap_query = LdapSearch(domain, dc_ip, username, password)
	ldap_query.init_all()
	ldap_query.exec(action)



