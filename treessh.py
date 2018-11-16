#!/usr/bin/env python
# -*- coding: utf-8 -*-

from src.database import db, structure
from src.proof import proof_of_work
from src.cryptography import keys, address, messages, encrypt, decrypt
from src.check import operations, node
from src import identifier,new_data,online_status,other_nodes,user,connection,command,disconnection,encryption,upload,download
from flask import Flask, render_template, request, redirect
from hashlib import sha256
import setup
import requests
import ConfigParser
import sys
import os, os.path
import inspect
import time
import sqlite3 as sql
import thread
import ipaddress
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.CRITICAL)

accounts = []
nodes = ["::ffff:185.243.113.106","::ffff:185.243.113.108","::ffff:185.243.113.59"]
connections = []
GetFromSettings = {}
PostToSettings = {}
PostTo = []
my_data = []
my_transactions = []
users = {}
users_search = []
last_ok = {}
current_directories = {}
connected_get_to_nodes = 0
connected_post_to_nodes = 0

path = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
config = ConfigParser.RawConfigParser()
config.read("treesshc")

app = Flask(__name__, template_folder='templates', static_url_path='')

try:
	print "[!] Checking accounts"
	con = sql.connect("info.db", check_same_thread=False)
	con.row_factory = sql.Row
	cur = con.cursor()
	cur.execute('SELECT * FROM accounts')
	Accounts = cur.fetchall()
	cur.execute('SELECT * FROM fake_account')
	FakeAccounts = cur.fetchall()
except:
	result = setup.config(path)
	if result == False:
		print "Something went wrong with installation. Exiting.."
		sys.exit(1)
	con = sql.connect("info.db", check_same_thread=False)
	con.row_factory = sql.Row
	cur = con.cursor()
	cur.execute('SELECT * FROM accounts')
	Accounts = cur.fetchall()
	cur.execute('SELECT * FROM fake_account')
	FakeAccounts = cur.fetchall()

if len(Accounts) == 0:
	print "	[!] Generating new account"
	private_key_hex,public_key_hex,Accountaddress = address.generate_account()
	try:
		cur.execute('INSERT INTO accounts (identifier,private_key_hex,public_key_hex) VALUES (?,?,?)', (Accountaddress,private_key_hex,public_key_hex))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)

	try:
		priv_key,pub_key = keys.generate()
	except:
		print "		[-] Error generating private/public keys pair. Exiting.."
		sys.exit(1)

	try:
		cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (Accountaddress,pub_key,priv_key,str(time.time())))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)

	print "		[+] New account " + Accountaddress + " created"
	GetFromSettings.update({Accountaddress:"ALL"})
	PostToSettings.update({Accountaddress:"ALL"})
	accounts.append(Accountaddress)
else:
	if len(Accounts) >= 2:
		print "	[-] You must only use one account! Exiting.."
		sys.exit(1)
	for Account in Accounts:
		try:
			account = Account["identifier"]
			private_key_hex = Account["private_key_hex"]
			public_key_hex = Account["public_key_hex"]
			Accountaddress = address.keyToAddr(public_key_hex,account)
			if Accountaddress != account:
				cur.execute('UPDATE accounts SET identifier=? WHERE identifier=?', (Accountaddress,account))
				con.commit()
			signature = messages.sign_message(private_key_hex,"test")
			if signature == False:
				print "	[-] There was a problem with signature. Exiting.."
				sys.exit(1)
			prove_ownership = messages.verify_message(public_key_hex, signature.encode("hex"), "test")
			if prove_ownership == False:
				print "	[-] The private key " + private_key_hex + " does not prove ownership of " + account
				cur.execute('DELETE FROM accounts WHERE identifier=?', (account,))
				con.commit()
			else:
				print "	[+] Account successfully loaded: " + account
				accounts.append(account)
		except:
			print "	[-] Error with private key. Maybe wrong format (WIF)? Exiting.."
			sys.exit(1)

if len(FakeAccounts) == 0:
	print "	[!] Generating new fake account"
	fake_private_key_hex,fake_public_key_hex,fakeAccountaddress = address.generate_fakeIdentifier()
	try:
		cur.execute('INSERT INTO fake_account (fakeidentifier,fake_private_key_hex,fake_public_key_hex) VALUES (?,?,?)', (fakeAccountaddress,fake_private_key_hex,fake_public_key_hex))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)
	print "		[+] New fake account " + fakeAccountaddress + " created"
elif len(FakeAccounts) == 1:
	try:
		fake_account = FakeAccounts[0]["fakeidentifier"]
		fake_private_key_hex = FakeAccounts[0]["fake_private_key_hex"]
		fake_public_key_hex = FakeAccounts[0]["fake_public_key_hex"]
		fake_Accountaddress = address.keyToAddr2(fake_public_key_hex,fake_account)
		if fake_Accountaddress != fake_account:
			cur.execute('UPDATE fake_account SET identifier=? WHERE identifier=?', (fake_Accountaddress,fake_account))
			con.commit()
		signature = messages.sign_message(fake_private_key_hex,"test")
		if signature == False:
			print "	[-] There was a problem with signature. Exiting.."
			sys.exit(1)
		prove_ownership = messages.verify_message(fake_public_key_hex, signature.encode("hex"), "test")
		if prove_ownership == False:
			print "	[-] The private key " + fake_private_key_hex + " does not prove ownership of " + fake_account
			cur.execute('DELETE FROM fake_account WHERE identifier=?', (fake_account,))
			con.commit()
		else:
			print "	[+] Fake account successfully loaded: " + fake_account
	except:
		print "	[-] Error with private key. Maybe wrong format (WIF)? Exiting.."
		sys.exit(1)
else:
	print "	[-] More than one fake account detected. Exiting.."
	sys.exit(1)

for account in accounts:
	try:
		post_to_setting = config.get(account, 'PostTo')
		post_to_setting = post_to_setting.replace(" ","")
		PostToSettings.update({account:post_to_setting})
	except:
		PostToSettings.update({account:"ALL"})

	try:
		get_from_setting = config.get(account, 'GetFrom')
		get_from_setting = get_from_setting.replace(" ","")
		GetFromSettings.update({account:get_from_setting})
	except:
		GetFromSettings.update({account:"ALL"})

cur.execute('DELETE FROM now_connected')
con.commit()

cur.execute('DELETE FROM connected_to_us')
con.commit()

cur.execute('DELETE FROM commands')
con.commit()

cur.execute('DELETE FROM downloads')
con.commit()

if not os.path.exists("uploads"):
    	os.makedirs("uploads")

if not os.path.exists("downloads"):
    	os.makedirs("downloads")

def whatis(ip):
	try:
		result = ipaddress.ip_address(unicode(ip))
		return str(result.version)
	except:
		return False

def memory_new(identifier,payload):
	result = operations.check_payload(payload)
	result_details = result.split(",")
	account = result_details[0]
	result = result_details[1]
	if result == "True":
		if account != identifier:
			return
		try:			
			result = node.constructor(payload)
			return result
		except:
			return "Error"
	else:
		return "None"

def ask_memory(account,peer):
	try:
		original_account = account
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
		result = cur.fetchall()
		if len(result) == 1:
			user = result[0]["identifier"]
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (user,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
		else:
			return
		cur.execute('SELECT * FROM fake_account')
		accounts = cur.fetchall()
		Account = accounts[0]["fakeidentifier"]
		fake_private_key_hex = accounts[0]["fake_private_key_hex"]
		fake_public_key_hex = accounts[0]["fake_public_key_hex"]
		fake_Address = address.keyToAddr2(fake_public_key_hex, Account)
		timestamp = str(int(time.time()))
		signature = messages.sign_message(fake_private_key_hex, fake_Address+":"+timestamp)
		fake_signature = signature.encode("hex")
		cur.execute('SELECT * FROM accounts WHERE identifier=?', (account,))
		accounts = cur.fetchall()
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		signature = messages.sign_message(private_key_hex, account+":"+timestamp)
		signature = signature.encode("hex")
		account = encrypt.encryptWithRSAKey(EncryptionKey,account)
		public_key_hex = encrypt.encryptWithRSAKey(EncryptionKey,public_key_hex)
		signature = encrypt.encryptWithRSAKey(EncryptionKey,signature)
		if account == False or public_key_hex == False or signature == False:
			return
		ip_result = whatis(peer)
		if ip_result == False:
			return
		if ip_result == "4":
			return_data = requests.get("http://"+peer+":12995/memory/search/"+Account+"/"+fake_public_key_hex+"/"+timestamp+"/"+fake_signature+"/"+account+"/"+public_key_hex+"/"+signature)
		else:
			return_data = requests.get("http://["+peer+"]:12995/memory/search/"+Account+"/"+fake_public_key_hex+"/"+timestamp+"/"+fake_signature+"/"+account+"/"+public_key_hex+"/"+signature)
		if return_data.content != "None" and return_data.status_code == 200:
			payload = decrypt.decryptWithRSAKey(EncryptionKey,return_data.content)
			if payload == False:
				return
			result = memory_new(original_account,payload)
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass

def send_online_status():
	try:
		global accounts
		for account in accounts:
			online_status.online_status(account)
	except (Exception,KeyboardInterrupt):
		pass
				
def get_other_nodes():
	try:
		for connection in connections:
			connection_details = connection.split(",")
			account = connection_details[0]
			peer = connection_details[1]
			other_nodes.get(peer)
	except (Exception,KeyboardInterrupt):
		pass
	
def connected_nodes():
	global connected_get_to_nodes
	global connected_post_to_nodes
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		for GetFromSetting in GetFromSettings:
			account = GetFromSetting
			setting = GetFromSettings[account]
			if setting == "ALL":
				times_found = 0
				for connection in connections:
					connection_details = connection.split(",")
					Account = connection_details[0]
					if Account == account:
						times_found += 1
				if times_found < 16:
					cur.execute('SELECT * FROM peers ORDER BY RANDOM() LIMIT ' + str(16-times_found))
					peers = cur.fetchall()
					if len(peers) > 0:
						for peer in peers:
							found = False
							Peer = peer["peer"]
							Identifier = peer["identifier"]
							for connection in connections:
								connection_details = connection.split(",")
								ACCOUNT = connection_details[0]
								PEER = connection_details[1]
								if ACCOUNT == account and Peer == PEER:
									found = True
									break
							if found == False and Identifier not in accounts:
								payload = account + "," + Peer
								connections.append(payload)
								connected_get_to_nodes += 1
								sys.stdout.write('\r[GET] -> Connections: %d | [POST] -> Connections: %d' % (connected_get_to_nodes,connected_post_to_nodes))
								sys.stdout.flush()
			elif setting != "NONE":
				peers = setting.replace(" ","")
				peers = peers.split(",")
				for peer in peers:
					found = False
					for connection in connections:
						connection_details = connection.split(",")
						ACCOUNT = connection_details[0]
						PEER = connection_details[1]
						if ACCOUNT == account and Peer == PEER:
							found = True
							break
					if found == False:
						cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
						result = cur.fetchall()
						if len(result) == 1:
							payload = account + "," + peer
							connections.append(payload)
							connected_get_to_nodes += 1
							sys.stdout.write('\r[GET] -> Connections: %d | [POST] -> Connections: %d' % (connected_get_to_nodes,connected_post_to_nodes))
							sys.stdout.flush()
		for PostToSetting in PostToSettings:
			account = PostToSetting
			setting = PostToSettings[account]
			if setting == "ALL":
				times_found = 0
				for connection in PostTo:
					connection_details = connection.split(",")
					Account = connection_details[0]
					if Account == account:
						times_found += 1
				if times_found < 16:
					cur.execute('SELECT * FROM peers ORDER BY RANDOM() LIMIT ' + str(16-times_found))
					peers = cur.fetchall()
					if len(peers) > 0:
						for peer in peers:
							found = False
							Identifier = peer["identifier"]
							Peer = peer["peer"]
							for connection in PostTo:
								connection_details = connection.split(",")
								ACCOUNT = connection_details[0]
								PEER = connection_details[1]
								if ACCOUNT == account and Peer == PEER:
									found = True
									break
							if found == False and Identifier not in accounts:
								payload = account + "," + Peer
								PostTo.append(payload)
								connected_post_to_nodes += 1
								sys.stdout.write('\r[GET] -> Connections: %d | [POST] -> Connections: %d' % (connected_get_to_nodes,connected_post_to_nodes))
								sys.stdout.flush()
			elif setting != "NONE":
				peers = setting.replace(" ","")
				peers = peers.split(",")
				for peer in peers:
					found = False
					for connection in PostTo:
						connection_details = connection.split(",")
						ACCOUNT = connection_details[0]
						PEER = connection_details[1]
						if ACCOUNT == account and Peer == PEER:
							found = True
							break
					if found == False:
						cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
						result = cur.fetchall()
						if len(result) == 1:
							payload = account + "," + peer
							PostTo.append(payload)
							connected_post_to_nodes += 1
							sys.stdout.write('\r[GET] -> Connections: %d | [POST] -> Connections: %d' % (connected_get_to_nodes,connected_post_to_nodes))
							sys.stdout.flush()
	except (Exception,KeyboardInterrupt):
		pass
	finally:
		try:
			con.close()
		except:
			pass
	
def ask_for_new_data():
	try:
		for connection in connections:
			connection_details = connection.split(",")
			account = connection_details[0]
			peer = connection_details[1]
			ask_memory(account,peer)
	except (Exception,KeyboardInterrupt):
		pass

def app_server():
	try:
		print "[!] Trying to start Flask server"
		print "	[+] Flask server started!"
		app.run(host='127.0.0.1', port=10001, threaded=True)
	except (Exception,KeyboardInterrupt):
		pass

def daemon():
	daemon_data_enabled = False
	Last_check = 0
	Last_online = 0
	Last_search = 0
	Last_peers_check = 0
	Last_users_check = 0
	Last_cleanup_check = 0
	global connected_get_to_nodes
	global connected_post_to_nodes
	global my_data
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	while True:
		if daemon_data_enabled == False:
			thread.start_new_thread(app_server,())
			daemon_data_enabled = True
		try:
			cur.execute('SELECT * FROM keys')
			results = cur.fetchall()
			if len(results) > 0:
				checks = 0
				while checks < len(results):
					time_now = time.time()
					timestamp = results[checks]["time_generated"]
					if time_now - float(timestamp) > 900:
						cur.execute('DELETE FROM keys WHERE time_generated=?', (timestamp,))
						con.commit()
					checks += 1
		except:
			pass

		try:
			cur.execute('SELECT * FROM test_peers')
			results = cur.fetchall()
			for result in results:
				peer = result["peer"]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					identifier.get(peer)
				cur.execute('DELETE FROM test_peers WHERE peer=?', (peer,))
				con.commit()
		except:
			pass
		
		if time.time() - Last_peers_check > 300:
			try:
				cur.execute('SELECT * FROM peers')
				results = cur.fetchall()
				for result in results:
					peer = result["peer"]
					identifier.get(peer)
				for node in nodes:
					cur.execute('SELECT * FROM peers WHERE peer=?', (node,))
					result = cur.fetchall()
					if len(result) == 0:
						identifier.get(node)
				Last_peers_check = time.time()
			except:
				pass

		if time.time() - Last_users_check > 60:
			try:
				if len(users_search) > 0:
					for user_search in users_search:
						cur.execute('SELECT * FROM users WHERE identifier=?', (user_search,))
						result = cur.fetchall()
						if len(result) == 0:
							for connection in connections:
								connection_details = connection.split(",")
								peer = connection_details[1]
								userDetails = user.get(peer,user_search)
								if userDetails != False:
									CHECK = online_status.check_payload(userDetails)
									check_details = CHECK.split(",")
									result = check_details[0]
									pubKey = check_details[1]
									last_online = check_details[2]
									if result == "True":
										payload = user_search + "," + pubKey + "," + last_online
										requests.post("http://127.0.0.1:10001/users/new", data=payload)
										cur.execute('INSERT INTO users (identifier,EncryptionKey,NewEncryptionKey,time_generated,encryption) VALUES (?,?,?,?,?)', (user_search,"0","0","0","OUTGOING"))
										con.commit()
										users_search.remove(user_search)
										break
							Last_users_check = time.time()
						else:
							users_search.remove(user_search)
			except:
				pass

		try:
			cur.execute('SELECT * FROM users WHERE encryption=?', ("OUTGOING",))
			results = cur.fetchall()
			for result in results:
				User = result["identifier"]
				time_generated = result["time_generated"]
				EncryptionKey = result["EncryptionKey"]
				if time.time() - float(time_generated) > 650 or EncryptionKey == "0":
					found = False
					for connection in connections:
						connection_details = connection.split(",")
						peer = connection_details[1]
						userDetails = user.get(peer,User)
						if userDetails != False:
							CHECK = online_status.check_payload(userDetails)
							check_details = CHECK.split(",")
							result = check_details[0]
							pubKey = check_details[1]
							last_online = check_details[2]
							if result == "True":
								payload = User + "," + pubKey + "," + last_online
								requests.post("http://127.0.0.1:10001/users/new", data=payload)
								found = True
								break
					if found == True:
						EncryptionKey = os.urandom(32)
						EncryptionKey = EncryptionKey.encode("hex")
						result = encryption.get_encryption(User,EncryptionKey)
						if result == True:
							time_generated = int(time.time())
							cur.execute('UPDATE users SET EncryptionKey=?,NewEncryptionKey=?,time_generated=? WHERE identifier=?', ("1",EncryptionKey,time_generated,User))
							con.commit()
		except Exception as e:
			print e
			pass

		try:
			for connection in connections:
				connection_details = connection.split(",")
				account = connection_details[0]
				peer = connection_details[1]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					connections.remove(connection)
					connected_get_to_nodes -= 1
					sys.stdout.write('\r[GET] -> Connections: %d | [POST] -> Connections: %d' % (connected_get_to_nodes,connected_post_to_nodes))
					sys.stdout.flush()
			for connection in PostTo:
				connection_details = connection.split(",")
				account = connection_details[0]
				peer = connection_details[1]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					PostTo.remove(connection)
					connected_post_to_nodes -= 1
					sys.stdout.write('\r[GET] -> Connections: %d | [POST] -> Connections: %d' % (connected_get_to_nodes,connected_post_to_nodes))
					sys.stdout.flush()
		except:
			pass
		
		try:
			for account in accounts:
				cur.execute('SELECT * FROM keys WHERE identifier=? ORDER BY time_generated DESC LIMIT 1', (account,))
				results = cur.fetchall()
				if len(results) > 0:
					last_generated = results[0]["time_generated"]
					if time.time() - float(last_generated) >= 300:
						priv_key,pub_key = keys.generate()
						time_now = time.time()
						cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (account,pub_key,priv_key,str(time_now)))
						con.commit()
				else:
					priv_key,pub_key = keys.generate()
					time_now = time.time()
					cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (account,pub_key,priv_key,str(time_now)))
					con.commit()
		except:
			pass

		try:
			if len(my_data) > 0:
				peers_to_post = []
				for connection in PostTo:
					connection_details = connection.split(",")
					peer = connection_details[1]
					if peer not in peers_to_post:
						peers_to_post.append(peer)
				for data_to_post in my_data:
					if len(PostTo) > 0:
						data_to_post_details = data_to_post.split(",")
						receiver = data_to_post_details[2]
						if receiver in accounts:
							for peer in peers_to_post:
								new_data.new_data(peer,data_to_post)
							my_data.remove(data_to_post)
						else:
							return_data = requests.get("http://127.0.0.1:10001/sent/"+receiver)
							try:
								times = return_data.content
								if int(times) - 1 <= 10:
									for peer in peers_to_post:
										new_data.new_data(peer,data_to_post)
									my_data.remove(data_to_post)
							except:
								pass
		except:
			pass

		try:
			for transaction in my_transactions:
				details = transaction.split(",")
				timestamp = details[1]
				if time.time() - float(timestamp) > 2000:
					my_transactions.remove(transaction)
		except:
			pass

		try:
			for User in users:
				details = users[User]
				details = details.split(",")
				timestamp = details[1]
				if time.time() - float(timestamp) > 360:
					users.pop(User)
		except:
			pass

		if time.time() - Last_cleanup_check > 10:
			try:
				cur.execute('DELETE FROM commands WHERE response!=?', ("None",))
				con.commit()
				cur.execute('SELECT * FROM commands WHERE response=?', ("None",))
				results = cur.fetchall()
				for result in results:
					time_queried = result["time_queried"]
					if time.time() - float(time_queried) > 600:
						cur.execute('DELETE FROM commands WHERE time_queried=?', (time_queried,))
						con.commit()
				Last_cleanup_check = time.time()
			except:
				pass

		if time.time() - Last_check > 60:
			connected_nodes()
			get_other_nodes()
			Last_check = time.time()
		if time.time() - Last_online > 300:
			send_online_status()
			Last_online = time.time()
		if time.time() - Last_search > 2:
			ask_for_new_data()
			Last_search = time.time()

@app.route('/tx/new', methods=['POST'])
def my_transactions_add():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		data = request.data
		found = False
		for my_transaction in my_transactions:
			my_transaction_details = my_transaction.split(",")
			tx_hash = my_transaction_details[0]
			if data == tx_hash:
				found = True
				break
		if found == False:
			my_transactions.append(data+","+str(int(time.time())))
		return "Done"
	else:
		abort(403)

@app.route('/tx/<tx>', methods=['GET'])
def check_transaction(tx):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		for transaction in my_transactions:
			details = transaction.split(",")
			tx_hash = details[0]
			if tx_hash == tx:
				found = True
				break
		return str(found)
	else:
		abort(403)

@app.route('/data/pool/search/<tx>', methods=['GET'])
def data_pool_search(tx):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		for data_in_pool in my_data:
			data_in_pool_details = data_in_pool.split(",")
			TX_HASH = data_in_pool_details[8]
			if TX_HASH == tx:
				found = True
				break
		return str(found)
	else:
		abort(403)

@app.route('/data/pool/new', methods=['POST'])
def data_pool_new():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		data = request.data
		if data not in my_data:
			my_data.append(data)
		return "Done"
	else:
		abort(403)

@app.route('/user/<User>', methods=['GET'])
def check_user(User):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		try:
			details = users[User]
			details = details.split(",")
			public_key = details[0]
			return public_key
		except:
			return "None"
	else:
		abort(403)

@app.route('/users/new', methods=['POST'])
def users_add():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		data = request.data
		data_details = data.split(",")
		user = data_details[0]
		public_key = data_details[1]
		last_online = data_details[2]
		found = False
		for USER in users:
			if USER == user:
				found = True
				break
		if found == True:
			users[user] = public_key + "," + last_online
		else:
			users.update({user:public_key + "," + last_online})
		return "Done"
	else:
		abort(403)

@app.route('/user/search', methods=['POST'])
def user_search():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		data = request.data
		if len(data) < 36 or len(data) > 50:
			return "False"
		else:
			if data not in users_search:
				users_search.append(data)
		return "Done"
	else:
		abort(403)

@app.route('/active_directory/<receiver>/change', methods=['POST'])
def active_directory_change(receiver):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		global current_directories
		found = False
		for USER in current_directories:
			if USER == receiver:
				found = True
				break
		if found == True:
			current_directories[receiver] = request.data
		return "OK"
	else:
		abort(403)

@app.route('/active_directory/<receiver>', methods=['GET'])
def active_directory_receiver(receiver):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		for USER in current_directories:
			if USER == receiver:
				found = True
				break
		if found == False:
			current = os.path.dirname(os.path.abspath(__file__))
			current_directories.update({receiver:current})
		return str(current_directories[receiver])
	else:
		abort(403)

@app.route('/active_directory', methods=['GET'])
def active_directory():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		return str(os.path.dirname(os.path.abspath(__file__)))
	else:
		abort(403)

@app.route('/sent/<receiver>', methods=['GET'])
def sent(receiver):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		for USER in last_ok:
			if USER == receiver:
				found = True
				break
		if found == True:
			last_ok[receiver] = last_ok[receiver] + 1
		else:
			last_ok.update({receiver:1})
		return str(last_ok[receiver])
	else:
		abort(403)

@app.route('/received/<sender>/OK', methods=['GET'])
def received_OK(sender):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		for USER in last_ok:
			if USER == sender:
				found = True
				break
		if found == True:
			last_ok[sender] = 0
		else:
			last_ok.update({sender:0})
		return "Done"
	else:
		abort(403)
 
if __name__ == "__main__":
	arguments = len(sys.argv)
	if arguments < 2:
		print "\n~~~oO0" + " Options " + "0Oo~~~\n"
		print "listen		Listens for connections"
		print "connect user	Tries to connect to remote user"
		print "\n~~~oO0" + " Examples " + "0Oo~~~\n"
		print "python treessh.py listen"
		print "python treessh.py connect " + accounts[0]
		sys.exit(1)
	elif arguments == 2:
		command = sys.argv[1]
		if command == "listen":
			thread.start_new_thread(daemon,())
			print "\n[!] Waiting for a user to connect."
			while True:
				cur.execute('SELECT * FROM connected_to_us')
				result = cur.fetchall()
				if len(result) == 1:
					user_connected = result[0]["user_connected"]
					print "[+] User " + user_connected + " connected"
					break
				else:
					try:
						time.sleep(2)
					except KeyboardInterrupt:
						print "[-] You pressed Ctrl+C , exiting.."
						sys.exit(1)
			while True:
				try:
					cur.execute('SELECT * FROM connected_to_us WHERE user_connected=?', (user_connected,))
					result = cur.fetchall()
					if len(result) == 0:
						print "[-] User " + user_connected + " disconnected"
						break
					else:
						time.sleep(2)
				except KeyboardInterrupt:
					disconnection.disconnect_from(user_connected)
					cur.execute('DELETE FROM connected_to_us')
					con.commit()
					print "[-] You pressed Ctrl+C , exiting.."
					sys.exit(1)
		else:
			print "Invalid command."
			sys.exit(1)
	elif arguments == 3:
		command1 = sys.argv[1]
		command2 = sys.argv[2]
		if command1 == "connect":
			if len(command2) < 36 or len(command2) > 50:
				print "Invalid user."
				sys.exit(1)
			thread.start_new_thread(daemon,())
			time.sleep(5)
			result = connection.connect_to(command2)
			if result != True:
				result = False
				print "\n[-] It seems that user is either offline or we need to exchange encryption keys."
			tries = 0
			while result != True:
				result = connection.connect_to(command2)
				if result == True:
					break
				else:
					tries += 1
					if tries == 60:
						print "[-] It seems that user is offline. Exiting.."
						sys.exit(1)
					time.sleep(5)
			print "\n[!] Trying to connect to: " + command2
			connection_time = str(int(time.time()))
			cur.execute('INSERT INTO now_connected (connected_to,time_connected) VALUES (?,?)', (command2,connection_time))
			con.commit()
			while True:
				cur.execute('SELECT * FROM now_connected WHERE connected_to=? AND command_line!=?', (command2,"None"))
				result = cur.fetchall()
				if len(result) == 1:
					command_line = result[0]["command_line"]
					print
					break
				else:
					if time.time() - float(connection_time) > 300:
						print "[-] It seems that user is either offline or refused the connection."
						sys.exit(1)
					time.sleep(2)
			while True:
				try:
					Command = raw_input(command_line + " ")
					if "UPLOAD " in Command or "upload " in Command:
						Command = Command.replace("UPLOAD ","")
						Command = Command.replace("upload ","")
						Command_files = Command.split(",")
						valid_files = True
						for Command_file in Command_files:
							if os.path.isfile(os.path.join("uploads","",Command_file)) == False:
								valid_files = False
								break
						if valid_files == False:
							print "[-] File " + Command_file + " doesn't exist."
						else:
							for Command_file in Command_files:
								result = upload.upload_file(command2,Command_file)
								tries = 0
								while result == False and tries < 60:
									result = upload.upload_file(command2,Command_file)
									if result == False:
										tries += 1
										time.sleep(2)
								if tries >= 60:
									print "[-] It seems that user disconnected."
									sys.exit(1)
								print "[+] File " + Command_file + " added to uploads queue"
					elif "DOWNLOAD " in Command or "download " in Command:
						Command = Command.replace("DOWNLOAD ","")
						Command = Command.replace("download ","")
						Command_files = Command.split(",")
						for Command_file in Command_files:
							unique_id = os.urandom(32)
							unique_id = unique_id.encode("hex")
							unique_id = sha256(unique_id.rstrip()).hexdigest()
							result = download.download_file(command2,unique_id,Command_file)
							tries = 0
							while result == False and tries < 60:
								result = download.download_file(command2,unique_id,Command_file)
								if result == False:
									tries += 1
									time.sleep(2)
							if tries >= 60:
								print "[-] It seems that user disconnected."
								sys.exit(1)
							print "[+] File " + Command_file + " added to downloads queue"
					else:
						unique_id = os.urandom(32)
						unique_id = unique_id.encode("hex")
						unique_id = sha256(unique_id.rstrip()).hexdigest()
						result = command.create_command(command2,unique_id,Command)
						tries = 0
						while result == False and tries < 60:
							result = command.create_command(command2,unique_id,Command)
							if result == False:
								tries += 1
								time.sleep(2)
						if tries >= 60:
							print "[-] It seems that user disconnected."
							sys.exit(1)
						command_time = time.time()
						while True:
							cur.execute('SELECT * FROM commands WHERE unique_id=?', (unique_id,))
							result = cur.fetchall()
							if len(result) == 1:
								response = result[0]["response"]
								if response == "None":
									if time.time() - command_time > 300:
										print "[-] It seems that user disconnected."
										sys.exit(1)
									time.sleep(2)
								else:
									print response
									break
				except KeyboardInterrupt:
					disconnection.disconnect_from(command2)
					cur.execute('DELETE FROM now_connected')
					con.commit()
					print "You pressed Ctrl+C , exiting.."
					sys.exit(1)
		else:
			print "Invalid command."
	else:
		print "Invalid command."
