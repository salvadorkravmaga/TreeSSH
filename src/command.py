from src.cryptography import address, messages, encrypt
from hashlib import sha256
import time
import sqlite3 as sql
import requests

def create_payload(sender,unique_id,command):
	try:
		additional1 = "COMMAND"
		additional2 = unique_id
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM accounts')
		accounts = cur.fetchall()
		account = accounts[0]["identifier"]
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
		result = cur.fetchall()
		if len(result) == 1:
			key = result[0]["EncryptionKey"]
		else:
			requests.post("http://127.0.0.1:10001/user/search", data=sender)
			return "User is offline"
		data = command
		data = encrypt.encryptWithRSAKey(key, data)
		timestamp = str(int(time.time()))
		final = "TREESSH" + ":" + account + ":" + sender + ":" + timestamp + ":" + additional1 + ":" + additional2 + ":" + public_key_hex + ":" + data
		tx_hash = sha256(final.rstrip()).hexdigest()
		signature = messages.sign_message(private_key_hex, tx_hash)
		payload = "TREESSH" + "," + account + "," + sender + "," + timestamp + "," + additional1 + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
		cur.execute('INSERT INTO commands (sender,unique_id,time_queried) VALUES (?,?,?)', (sender,unique_id,timestamp))
		con.commit()
		return payload
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass

def create_command(sender,unique_id,command):
	try:
		payload = create_payload(sender,unique_id,command)
		if sender in payload:
			return_data = requests.post("http://127.0.0.1:10001/data/pool/new", data=payload)
			return True
		else:
			return payload
	except:
		return False
