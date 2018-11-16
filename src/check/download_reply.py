from src.cryptography import address, messages, encrypt
from hashlib import sha256
import time
import sqlite3 as sql
import requests
import os
import math

def send_file(sender,unique_id,filename):
	try:
		additional1 = "DOWNLOAD-REPLY"
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
		return_data = requests.get("http://127.0.0.1:10001/active_directory/"+sender)
		path = return_data.content
		if os.path.isfile(os.path.join(path,"",filename)) == False:
			return False
		filesize = os.path.getsize(os.path.join(path,"",filename))
		filesize = float(filesize) / float(1048576)
		total_parts = int(math.ceil(filesize))
		if filesize <= 1 and filesize > 0:
			filename2 = encrypt.encryptWithRSAKey(key, filename)
			filename_details = encrypt.encryptWithRSAKey(key, "1/1")
			additional2 = unique_id + "|" + filename2 + "|" + filename_details
			with open(os.path.join(path,"",filename), "rb") as file_to_send:
				bytes = file_to_send.read(1048576)
			data = encrypt.encryptWithRSAKey(key, bytes)
			timestamp = str(int(time.time()))
			final = "TREESSH" + ":" + account + ":" + sender + ":" + timestamp + ":" + additional1 + ":" + additional2 + ":" + public_key_hex + ":" + data
			tx_hash = sha256(final.rstrip()).hexdigest()
			signature = messages.sign_message(private_key_hex, tx_hash)
			payload = "TREESSH" + "," + account + "," + sender + "," + timestamp + "," + additional1 + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
			return_data = requests.post("http://127.0.0.1:10001/data/pool/new", data=payload)
			return True
		elif filesize > 1:
			filename2 = encrypt.encryptWithRSAKey(key, filename)
			starting = 1
			with open(os.path.join(path,"",filename), "rb") as file_to_send:
				filename_details = encrypt.encryptWithRSAKey(key, str(starting) + "/" + str(total_parts))
				additional2 = unique_id + "|" + filename2 + "|" + filename_details
				bytes = file_to_send.read(1048576)
				data = encrypt.encryptWithRSAKey(key, bytes)
				timestamp = str(int(time.time()))
				final = "TREESSH" + ":" + account + ":" + sender + ":" + timestamp + ":" + additional1 + ":" + additional2 + ":" + public_key_hex + ":" + data
				tx_hash = sha256(final.rstrip()).hexdigest()
				signature = messages.sign_message(private_key_hex, tx_hash)
				payload = "TREESSH" + "," + account + "," + sender + "," + timestamp + "," + additional1 + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
				return_data = requests.post("http://127.0.0.1:10001/data/pool/new", data=payload)
				while bytes != "" and starting < total_parts:
					starting += 1
					filename_details = encrypt.encryptWithRSAKey(key, str(starting) + "/" + str(total_parts))
					additional2 = unique_id + "|" + filename2 + "|" + filename_details
					bytes = file_to_send.read(1048576)
					data = encrypt.encryptWithRSAKey(key, bytes)
					timestamp = str(int(time.time()))
					final = "TREESSH" + ":" + account + ":" + sender + ":" + timestamp + ":" + additional1 + ":" + additional2 + ":" + public_key_hex + ":" + data
					tx_hash = sha256(final.rstrip()).hexdigest()
					signature = messages.sign_message(private_key_hex, tx_hash)
					payload = "TREESSH" + "," + account + "," + sender + "," + timestamp + "," + additional1 + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
					return_data = requests.post("http://127.0.0.1:10001/data/pool/new", data=payload)
			return True
		return False
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass
