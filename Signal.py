import base64
import secrets
import os
import json

import hmac

from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
#from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

BITS = 32
FORMAT = "utf-8"
current_directory = os.getcwd()

def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode('utf-8').strip()

def pad(msg):
	# pkcs7 padding
	num = 16 - (len(msg) % 16)
	return msg + bytes([num] * num)

def unpad(msg):
	# remove pkcs7 padding
	return msg[:-msg[-1]]

def KDF_RK(rk, dh_out):
	out = HKDF(dh_out, 64, rk, SHA256, 1)
	#HKDF(SHA256, 64, rk, b'0x00').derive(dh-out)	#For use with cryptography.hazmat.primitives.kdf.hkdf
	rk_input_material = out[:32]
	ck = out[32:]
	return rk_input_material, ck

def KDF_CK(ck):
	mk = hmac.new(ck, msg = b'0x01', digestmod = SHA256).digest()
	ck_input_material = hmac.new(ck, msg = b'0x02', digestmod = SHA256).digest()
	return ck_input_material, mk


class User(object):

	def __init__(self, name):
		path_users = os.path.join(current_directory, "Users")
		if not os.path.isdir(path_users):
			os.mkdir(path_users)

		self.USER_FILE_NAME = "Users/" + name + ".json"
		path_users = os.path.join(current_directory, self.USER_FILE_NAME)
		if not os.path.isfile(path_users):
			data = {}
			json_object = json.dumps(data, indent = 4)

			with open(self.USER_FILE_NAME, "w") as outfile:
				outfile.write(json_object)

		self.dr_keys = {}

	def RatchetEncrypt(self, username, plaintext, AD):
		print("message =", plaintext)
		print("username =", username)
		print(self.dr_keys)
		print("send_ratchet :", self.dr_keys[username]["CKs"])

		CKs, mk = KDF_CK(self.dr_keys[username]["CKs"].to_bytes(BITS, 'big'))
		self.dr_keys[username]["CKs"] = int.from_bytes(CKs, 'big')

		header = self.HEADER(self.dr_keys[username]["DHs"], self.dr_keys[username]["PN"], self.dr_keys[username]["Ns"]) 
		self.dr_keys[username]["Ns"] += 1
		#print(header, '\n')

		#SAVE DATA
		with open(self.USER_FILE_NAME) as json_file:
			dictionary = json.load(json_file)
			dictionary[username] = {
				"RK"  : self.dr_keys[username]["RK"],
				"DHs" : self.dr_keys[username]["DHs"],
				"DHr" : self.dr_keys[username]["DHr"],
				"CKs" : self.dr_keys[username]["CKs"],
				"CKr" : self.dr_keys[username]["CKr"],
				"Ns"  : self.dr_keys[username]["Ns"],
				"Nr"  : self.dr_keys[username]["Nr"],
				"PN"  : self.dr_keys[username]["PN"]
			}
		with open(self.USER_FILE_NAME, 'w') as outfile:
			json.dump(dictionary, outfile, indent = 4)

		return header, self.ENCRYPT(mk, plaintext, self.CONCAT(AD, header))

	def ENCRYPT(self, mk, plaintext, AD):
		print("MK =", mk)
		output = HKDF(mk, 80, b'0x00' * 80, SHA256, 1)
		#output = HKDF(SHA256, 80, b'0x00' * 80, b'0x00').derive(mk)	#For use with cryptography.hazmat.primitives.kdf.hkdf
		ciphertext = AES.new(output[:32], AES.MODE_CBC, iv=output[64:]).encrypt(pad(plaintext))
		header = hmac.new(output[32:64], msg = AD, digestmod = SHA256).digest()
		#print(ciphertext, '\n')
		#print(header, '\n')

		l = len(ciphertext)
		bytes_l = (l).to_bytes(1, 'big')
		cipher = bytes_l + ciphertext + header
		return cipher

	def RatchetDecrypt(self, otherName, data):
		header_size = int.from_bytes(data[:1], 'big')
		data = data[1:]
		header_bytes = data[:header_size]
		data = data[header_size:]

		cipher_size = int.from_bytes(data[:1], 'big')
		data = data[1:]
		ciphertext = data[:cipher_size]
		data = data[cipher_size:]

		AD = data

		#print(header, '\n')
		#print(ciphertext, '\n')
		#print(AD, '\n')

		header = base64.b64decode(header_bytes)
		header = header.decode(FORMAT)
		header = header.replace("\'", "\"")
		header = json.loads(header)
		header_dh = header["DH"]

		#LOAD SAVED DATA
		with open(self.USER_FILE_NAME, 'r') as read_file:
			saved_data = json.load(read_file)
			for username, keys in saved_data.items():
				if username == otherName:
					self.dr_keys[otherName] = {
						"RK"  : keys["RK"],	
						"DHs" : keys["DHs"],
						"DHr" : keys["DHr"],
						"CKs" : keys["CKs"],
						"CKr" : keys["CKr"],
						"Ns"  : keys["Ns"],
						"Nr"  : keys["Nr"],
						"PN"  : keys["PN"]
					}
					break

		if(header_dh != self.dr_keys[otherName]["DHr"]):
			print("NEW DH PUBLIC KEY")
			self.DHRatchet(otherName, header_dh)

		print("recv_ratchet :", self.dr_keys[otherName]["CKr"])

		CKr, mk = KDF_CK(self.dr_keys[otherName]["CKr"].to_bytes(BITS, 'big'))
		self.dr_keys[otherName]["CKr"] = int.from_bytes(CKr, 'big')
		self.dr_keys[otherName]["Nr"] += 1

		#SAVE DATA
		with open(self.USER_FILE_NAME) as json_file:
			dictionary = json.load(json_file)
			dictionary[otherName] = {
				"RK"  : self.dr_keys[otherName]["RK"],
				"DHs" : self.dr_keys[otherName]["DHs"],
				"DHr" : self.dr_keys[otherName]["DHr"],
				"CKs" : self.dr_keys[otherName]["CKs"],
				"CKr" : self.dr_keys[otherName]["CKr"],
				"Ns"  : self.dr_keys[otherName]["Ns"],
				"Nr"  : self.dr_keys[otherName]["Nr"],
				"PN"  : self.dr_keys[otherName]["PN"]
			}
		with open(self.USER_FILE_NAME, 'w') as outfile:
			json.dump(dictionary, outfile, indent = 4)

		return self.DECRYPT(otherName, mk, ciphertext, self.CONCAT(AD, header_bytes))

	def DECRYPT(self, username, mk, ciphertext, AD):
		print("MK =", mk)
		output = HKDF(mk, 80, b'0x00' * 80, SHA256, 1)
		#output = HKDF(SHA256, 80, b'0x00' * 80, b'0x00').derive(mk)	#For use with cryptography.hazmat.primitives.kdf.hkdf
		print("cipher =", ciphertext)
		msg = unpad(AES.new(output[:32], AES.MODE_CBC, iv=output[64:]).decrypt(ciphertext))
		print("message =", msg)
		return msg
	
	def HEADER(self, DHs, PN, Ns):
		DH_pair = X25519PrivateKey.from_private_bytes(DHs.to_bytes(BITS, 'big'))

		DH_public_bytes = DH_pair.public_key().public_bytes(
			encoding=serialization.Encoding.Raw,
			format=serialization.PublicFormat.Raw)

		DH_public = int.from_bytes(DH_public_bytes, 'big')

		input_dict = {
		"DH" : DH_public,
		"PN" : PN,
		"Ns" : Ns
		}

		header = str(input_dict).encode(FORMAT)
		header_bytes = base64.b64encode(header)

		return(header_bytes)

	def CONCAT(self, AD, header):
		l = len(AD)
		bytes_l = (l).to_bytes(1, 'big')
		header = bytes_l + AD + header
		return header

	def DHRatchet(self, username, DH):
		self.dr_keys[username]["PN"] = self.dr_keys[username]["Ns"]
		self.dr_keys[username]["Ns"] = 0
		self.dr_keys[username]["Nr"] = 0
		self.dr_keys[username]["DHr"] = DH

		print("RK =", self.dr_keys[username]["RK"])
		RK, CKr = KDF_RK(self.dr_keys[username]["RK"].to_bytes(BITS, 'big'), X25519PrivateKey.from_private_bytes(self.dr_keys[username]["DHs"].to_bytes(BITS, 'big')).exchange(X25519PublicKey.from_public_bytes(self.dr_keys[username]["DHr"].to_bytes(BITS, 'big'))))
		self.dr_keys[username]["RK"] = int.from_bytes(RK, 'big')
		self.dr_keys[username]["CKr"] = int.from_bytes(CKr, 'big')

		print("recv_ratchet :", self.dr_keys[username]["CKr"])

		privateKey = X25519PrivateKey.generate()
		privateKey_bytes = privateKey.private_bytes(
								encoding = serialization.Encoding.Raw,
								format = serialization.PrivateFormat.Raw,
								encryption_algorithm = serialization.NoEncryption())
		self.dr_keys[username]["DHs"] = int.from_bytes(privateKey_bytes, 'big')


		RK, CKs = KDF_RK(self.dr_keys[username]["RK"].to_bytes(BITS, 'big'), X25519PrivateKey.from_private_bytes(self.dr_keys[username]["DHs"].to_bytes(BITS, 'big')).exchange(X25519PublicKey.from_public_bytes(self.dr_keys[username]["DHr"].to_bytes(BITS, 'big'))))
		self.dr_keys[username]["RK"] = int.from_bytes(RK, 'big')
		self.dr_keys[username]["CKs"] = int.from_bytes(CKs, 'big')


	def open_conv(self, otherName, server):
		with open(self.USER_FILE_NAME, 'r') as read_file:
			data = json.load(read_file)
			for username, keys in data.items():
				if username == otherName:
					#LOAD SAVED DATA
					self.dr_keys[otherName] = {
						"RK"  : keys["RK"],	
						"DHs" : keys["DHs"],
						"DHr" : keys["DHr"],
						"CKs" : keys["CKs"],
						"CKr" : keys["CKr"],
						"Ns"  : keys["Ns"],
						"Nr"  : keys["Nr"],
						"PN"  : keys["PN"]
					}
					return

		P = getPrime(BITS)
		G = secrets.randbits(BITS)

		privateKey = secrets.randbits(BITS)
		publicKey = pow(G, privateKey, P)
		print("publicKey =", publicKey)

		msg = "SK1 " + otherName + ' ' + str(P) + ' ' + str(G) + ' ' + str(publicKey)
		server.send(msg.encode(FORMAT))
		
		msg = server.recv(2048)

		otherDHr = X25519PublicKey.from_public_bytes(msg[:32])
		otherPublicKey = msg[32:].decode(FORMAT)
		sharedKey = pow(int(otherPublicKey), privateKey, P)

		print("otherPublicKey =", int(otherPublicKey))
		print("sharedKey =", sharedKey)

		DHs = X25519PrivateKey.generate()
		DHs_bytes = DHs.private_bytes(
			encoding = serialization.Encoding.Raw,
			format = serialization.PrivateFormat.Raw,
			encryption_algorithm = serialization.NoEncryption())

		DHr_bytes = msg[:32]

		print("Other Public DH Key :", int.from_bytes(DHr_bytes, 'big'))

		output = KDF_RK(sharedKey.to_bytes(BITS, 'big'), DHs.exchange(otherDHr))
		RK = output[0]
		CKs = output[1]

		self.dr_keys[otherName] = {
			"RK"  : int.from_bytes(RK, 'big'),	
			"DHs" : int.from_bytes(DHs_bytes, 'big'),
			"DHr" : int.from_bytes(DHr_bytes, 'big'),
			"CKs" : int.from_bytes(CKs, 'big'),
			"CKr" : None,
			"Ns"  : 0,
			"Nr"  : 0,
			"PN"  : 0
		}

		with open(self.USER_FILE_NAME) as json_file:
			dictionary = json.load(json_file)
			dictionary[otherName] = {
				"RK"  : int.from_bytes(RK, 'big'),
				"DHs" : int.from_bytes(DHs_bytes, 'big'),
				"DHr" : int.from_bytes(DHr_bytes, 'big'),
				"CKs" : int.from_bytes(CKs, 'big'),
				"CKr" : None,
				"Ns"  : 0,
				"Nr"  : 0,
				"PN"  : 0,
				"MKSKIPPED" : {}
			}
		with open(self.USER_FILE_NAME, 'w') as outfile:
			json.dump(dictionary, outfile, indent = 4)

		#TEST
	
		header, cipher = self.RatchetEncrypt(otherName, b'TEST_MSG_1', b'TEST_AD')
		l = len(header)
		bytes_l = (l).to_bytes(1, 'big')
		while len(otherName.encode(FORMAT)) < 16:
			otherName += ' '
		msg = b"DMS " + otherName.encode(FORMAT) + bytes_l + header + cipher
		server.send(msg)

		'''
		otherName = otherName.split(' ')[0]
		header, cipher = self.RatchetEncrypt(otherName, b'TEST_MSG_2', b'TEST_AD')
		l = len(header)
		bytes_l = (l).to_bytes(1, 'big')
		while len(otherName.encode(FORMAT)) < 16:
			otherName += ' '
		msg = b"DMS " + otherName.encode(FORMAT) + bytes_l + header + cipher
		server.send(msg)'''

	def create_SK(self, otherName, P, G, otherPublicKey, server):
		privateKey = secrets.randbits(BITS)
		publicKey = pow(int(G), privateKey, int(P))
		sharedKey = pow(int(otherPublicKey), privateKey, int(P))

		print("otherPublicKey =", int(otherPublicKey))
		print("publicKey =", publicKey)
		print("sharedKey =", sharedKey)

		DHs = X25519PrivateKey.generate()
		DHs_bytes = DHs.private_bytes(
			encoding = serialization.Encoding.Raw,
			format = serialization.PrivateFormat.Raw,
			encryption_algorithm = serialization.NoEncryption())

		DH_public = DHs.public_key().public_bytes(
			encoding=serialization.Encoding.Raw,
			format=serialization.PublicFormat.Raw)

		print("My Public DH Key :", int.from_bytes(DH_public, 'big'))

		publicKey_str = ' ' + str(publicKey)

		while len(otherName.encode(FORMAT)) < 16:
			otherName += ' '
		print("TEST 1")
		msg = ("SK2 " + otherName).encode(FORMAT) + DH_public + publicKey_str.encode(FORMAT)
		print("TEST 2")
		server.send(msg)

		self.dr_keys[otherName.split(' ')[0]] = {
			"RK" : sharedKey,	
			"DHs" : int.from_bytes(DHs_bytes, 'big'),
			"DHr" : None,
			"CKs" : None,
			"CKr" : None,
			"Ns" : 0,
			"Nr" : 0,
			"PN" : 0
		}

		with open(self.USER_FILE_NAME) as json_file:
			dictionary = json.load(json_file)
			dictionary[otherName] = {
				"RK" : sharedKey,
				"DHs" : int.from_bytes(DHs_bytes, 'big'),
				"DHr" : None, 
				"CKs" : None,
				"CKr" : None,
				"Ns" : 0,
				"Nr" : 0,
				"PN" : 0,
				"MKSKIPPED" : {}
			}
		with open(self.USER_FILE_NAME, 'w') as outfile:
			json.dump(dictionary, outfile, indent = 4)