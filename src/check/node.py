from src.cryptography import encrypt, decrypt, address, messages
from src.check import operations, connect_reply, command_reply, download_reply, encryption_reply, OK
from hashlib import sha256
import time
import sqlite3 as sql
import ConfigParser
import getpass
import socket
import os
import requests
import os.path

def tree_ssh(sender,receiver,timestamp,additional1,additional2,additional3,data,tx_hash,signature):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		con.text_factory = str
		cur = con.cursor()
	except:
		pass
	try:
		if additional1 == "CONNECT":
			if additional2 != "None":
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			if data != "None":
				return
			try:
				config = ConfigParser.RawConfigParser()
				config.read("treesshc")
				allowed_users_setting = config.get('Configuration', 'AllowedUsers')
				allowed_users = allowed_users_setting.split(",")
			except:
				allowed_users = []
			if sender not in allowed_users:
				return
			cur.execute('SELECT * FROM connected_to_us')
			result = cur.fetchall()
			if len(result) == 0:
				time_connected = str(int(time.time()))
				cur.execute('INSERT INTO connected_to_us (user_connected,time_connected) VALUES (?,?)', (sender,time_connected))
				con.commit()
				user = getpass.getuser()
				hostname = socket.gethostname()
				command_line = user + "@" + hostname + ":~$"
				connect_reply.send_reply(sender,command_line)
				return True
			else:
				OK.send_OK(sender)
		elif additional1 == "CONNECT-REPLY":
			cur.execute('SELECT * FROM now_connected WHERE connected_to=?', (sender,))
			result = cur.fetchall()
			if len(result) == 0:
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			cur.execute('UPDATE now_connected SET command_line=? WHERE connected_to=?', (data,sender))
			con.commit()
		elif additional1 == "DISCONNECT":
			if additional2 != "None":
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			if data != "None":
				return
			cur.execute('SELECT * FROM connected_to_us WHERE user_connected=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				cur.execute('DELETE FROM connected_to_us')
				con.commit()
				return True
			cur.execute('SELECT * FROM now_connected WHERE connected_to=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				cur.execute('DELETE FROM now_connected')
				con.commit()
				return True
		elif additional1 == "COMMAND":
			if len(additional2) != 64:
				return
			cur.execute('SELECT * FROM connected_to_us WHERE user_connected=?', (sender,))
			result = cur.fetchall()
			if len(result) == 0:
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			while data[0] == " ":
				data = data[1:]
			return_data = requests.get("http://127.0.0.1:10001/active_directory/"+sender)
			path = return_data.content
			return_data = requests.get("http://127.0.0.1:10001/active_directory")
			starting_folder = return_data.content
			try:
				if data == "cd":
					current_path = "/"
					while path != current_path:
						current_path = path
						path = os.path.abspath(os.path.join(path, os.pardir))
					requests.post("http://127.0.0.1:10001/active_directory/"+sender+"/change", data=path)
					result = "Directory changed."
				elif data == "cd .." or data == "cd..":
					path = os.path.abspath(os.path.join(path, os.pardir))
					requests.post("http://127.0.0.1:10001/active_directory/"+sender+"/change", data=path)
					result = "Directory changed."
				elif "cd" in data:
					details = data.split(" ")
					directory = details[1]
					if os.path.isdir(os.path.join(path,"",directory)) == True:
						path = os.path.join(path,"",directory)
						requests.post("http://127.0.0.1:10001/active_directory/"+sender+"/change", data=path)
						result = "Directory changed."
					else:
						result = "Directory doesn't exist."
				elif data == "ls" or data == "dir":
					if path != starting_folder:
						result = os.popen(data + " " + path).read()
					else:
						result = os.popen(data).read()
					result = result[0:-1]
				else:
					result = os.popen(data).read()
					result = result[0:-1]
			except:
				result = "Command not found."
			command_reply.send_reply(sender,additional2,result)
			return True
		elif additional1 == "COMMAND-REPLY":
			if len(additional2) != 64:
				return
			cur.execute('SELECT * FROM commands WHERE sender=? AND unique_id=? AND response=?', (sender,additional2,"None"))
			result = cur.fetchall()
			if len(result) == 0:
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			cur.execute('UPDATE commands SET response=? WHERE sender=? AND unique_id=?', (data,sender,additional2))
			con.commit()
			OK.send_OK(sender)
			return True
		elif additional1 == "UPLOAD":
			cur.execute('SELECT * FROM connected_to_us WHERE user_connected=?', (sender,))
			result = cur.fetchall()
			if len(result) == 0:
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
			try:
				details = additional2.split("|")
				filename = details[0]
				original_filename = filename
				filename_details = details[1]
			except:
				return
			filename = decrypt.decryptWithRSAKey(EncryptionKey,filename)
			original_filename = filename
			if filename == False:
				return
			filename_details = decrypt.decryptWithRSAKey(EncryptionKey,filename_details)
			if filename_details == False:
				return
			try:
				filename_details_details = filename_details.split("/")
				current_part = filename_details_details[0]
				total_parts = filename_details_details[1]
			except:
				return
			try:
				current_part = str(int(current_part))
				total_parts = str(int(total_parts))
			except:
				return
			if int(current_part) <= 0 or int(current_part) > int(total_parts) or int(total_parts) <= 0:
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			return_data = requests.get("http://127.0.0.1:10001/active_directory/"+sender)
			path = return_data.content
			if os.path.isfile(os.path.join(path,"",filename + "_" + current_part)) == True:
				os.remove(os.path.join(path,"",filename + "_" + current_part))
			with open(os.path.join(path,"",filename + "_" + current_part), "wb") as dest:
				dest.write(data)
			completed_file = True
			for i in range(1,int(total_parts)+1):
				if os.path.isfile(os.path.join(path,"",filename + "_" + str(i))) == False:
					completed_file = False
					break
			if completed_file == True:
				file_already_exists = False
				if os.path.isfile(os.path.join(path,"",filename)) == True:
					file_already_exists = True
				if file_already_exists == True:
					starting = 1
					found = False
					while found == False:
						os.path.join(path,"","(" + str(starting) + ")" + filename)
						if os.path.isfile("(" + str(starting) + ")" + filename) == False:
							filename = "(" + str(starting) + ")" + filename
							found = True
						starting += 1
				final_file = open(os.path.join(path,"",filename), "wb")
				for i in range(1,int(total_parts)+1):
					with open(os.path.join(path,"",original_filename + "_" + str(i)), 'r') as current_file:
    						content = current_file.read()
						final_file.write(content)
						os.remove(os.path.join(path,"",original_filename + "_" + str(i)))
				final_file.close()
			OK.send_OK(sender)
		elif additional1 == "DOWNLOAD":
			if len(additional2) != 64:
				return
			cur.execute('SELECT * FROM connected_to_us WHERE user_connected=?', (sender,))
			result = cur.fetchall()
			if len(result) == 0:
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
			filename = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if filename == False:
				return
			download_reply.send_file(sender,additional2,filename)
		elif additional1 == "DOWNLOAD-REPLY":
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
			additional2_details = additional2.split("|")
			unique_id = additional2_details[0]
			cur.execute('SELECT * FROM downloads WHERE sender=? AND unique_id=?', (sender,unique_id))
			result = cur.fetchall()
			if len(result) == 0:
				return
			filename = additional2_details[1]
			filename_details = additional2_details[2]
			filename = decrypt.decryptWithRSAKey(EncryptionKey,filename)
			if filename == False:
				return
			original_filename = filename
			cur.execute('SELECT * FROM downloads WHERE sender=? AND unique_id=? AND filename=?', (sender,unique_id,filename))
			result = cur.fetchall()
			if len(result) == 0:
				return
			filename_details = decrypt.decryptWithRSAKey(EncryptionKey,filename_details)
			if filename_details == False:
				return
			try:
				filename_details_details = filename_details.split("/")
				current_part = filename_details_details[0]
				total_parts = filename_details_details[1]
			except:
				return
			try:
				current_part = str(int(current_part))
				total_parts = str(int(total_parts))
			except:
				return
			if int(current_part) <= 0 or int(current_part) > int(total_parts) or int(total_parts) <= 0:
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			if os.path.isfile(os.path.join("downloads","",filename + "_" + current_part)) == True:
				os.remove(os.path.join("downloads","",filename + "_" + current_part))
			with open(os.path.join("downloads","",filename + "_" + current_part), "wb") as dest:
				dest.write(data)
			completed_file = True
			for i in range(1,int(total_parts)+1):
				if os.path.isfile(os.path.join("downloads","",filename + "_" + str(i))) == False:
					completed_file = False
					break
			if completed_file == True:
				file_already_exists = False
				if os.path.isfile(os.path.join("downloads","",filename)) == True:
					file_already_exists = True
				if file_already_exists == True:
					starting = 1
					found = False
					while found == False:
						if os.path.isfile(os.path.join("downloads","","(" + str(starting) + ")" + filename)) == False:
							filename = "(" + str(starting) + ")" + filename
							found = True
						starting += 1
				final_file = open(os.path.join("downloads","",filename), "wb")
				for i in range(1,int(total_parts)+1):
					with open(os.path.join("downloads","",filename + "_" + str(i)), 'r') as current_file:
    						content = current_file.read()
						final_file.write(content)
						os.remove(os.path.join("downloads","",filename + "_" + str(i)))
				final_file.close()
				cur.execute('DELETE FROM downloads WHERE sender=? AND unique_id=? AND filename=?', (sender,unique_id,filename))
				con.commit()
			OK.send_OK(sender)
		elif additional1 == "ENCRYPT":
			try:
				config = ConfigParser.RawConfigParser()
				config.read("treesshc")
				allowed_users_setting = config.get('Configuration', 'AllowedUsers')
				allowed_users = allowed_users_setting.split(",")
			except:
				allowed_users = []
			if sender not in allowed_users:
				return
			if additional2 != "None":
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 0:
				EncryptionKey = decrypt.decryptfromPubKey(data)
				if EncryptionKey == False:
					return
				try:
					testEncryptionKey = EncryptionKey.decode("hex")
				except:
					return
				result = encrypt.encryptWithRSAKey(EncryptionKey,"test")
				if result == False:
					return
				test_result = decrypt.decryptWithRSAKey(EncryptionKey,result)
				if test_result == False:
					return
				if test_result != "test":
					return
				time_created = str(int(time.time()))
				cur.execute('INSERT INTO users (identifier,EncryptionKey,NewEncryptionKey,time_generated,encryption) VALUES (?,?,?,?,?)', (sender,EncryptionKey,EncryptionKey,time_created,"INCOMING"))
				con.commit()
				result = encryption_reply.send_reply(sender,EncryptionKey)
				if result == True:
					return True
			elif len(result) == 1:
				time_generated = result[0]["time_generated"]
				encryption_type = result[0]["encryption"]
				if encryption_type == "INCOMING":
					if time.time() - float(time_generated) > 600:
						EncryptionKey = decrypt.decryptfromPubKey(data)
						if EncryptionKey == False:
							return
						try:
							testEncryptionKey = EncryptionKey.decode("hex")
						except:
							return
						Result = encrypt.encryptWithRSAKey(EncryptionKey,"test")
						if Result == False:
							return
						test_result = decrypt.decryptWithRSAKey(EncryptionKey,Result)
						if test_result == False:
							return
						if test_result != "test":
							return
						oldEncryptionKey = result[0]["EncryptionKey"]
						time_created = str(int(time.time()))
						cur.execute('UPDATE users SET EncryptionKey=?,NewEncryptionKey=?,time_generated=? WHERE identifier=?', (EncryptionKey,oldEncryptionKey,time_created,sender))
						con.commit()
						result = encryption_reply.send_reply(sender,EncryptionKey)
						if result == True:
							return True
			else:
				return
		elif additional1 == "ENCRYPT-REPLY":
			if additional2 != "None":
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["NewEncryptionKey"]
				encryption = result[0]["encryption"]
			else:
				return
			if encryption != "OUTGOING":
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			if data == EncryptionKey:
				cur.execute('UPDATE users SET EncryptionKey=? WHERE identifier=?', (data,sender))
				con.commit()
				OK.send_OK(sender)
		elif additional1 == "OK":
			requests.get("http://127.0.0.1:10001/received/"+sender+"/OK")
			return True
		else:
			return
	except:
		return
	finally:
		try:
			con.close()
		except:
			pass

def constructor(payload):
	details = payload.split(",")
	operation = details[0]
	sender = details[1]
	receiver = details[2]
	timestamp = details[3]
	additional1 = details[4]
	additional2 = details[5]
        additional3 = details[6]
	data = details[7]
	tx_hash = details[8]
	signature = details[9]
	result = tree_ssh(sender,receiver,timestamp,additional1,additional2,additional3,data,tx_hash,signature)
	return result
