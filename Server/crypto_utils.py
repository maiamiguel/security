import rsa
import os
import base64
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random

def generateKeys(keySize=4096, keyName='key', path=os.getcwd()):
	pub = open(path+'/'+keyName+'.pub','wb')
	priv = open(path+'/'+keyName+'.priv','wb')
	(pubkey, privkey) = rsa.newkeys(keySize,poolsize=2)
	pub.write(pubkey.save_pkcs1())
	priv.write(privkey.save_pkcs1())
	pub.close()
	priv.close()

def decryptRSA(privKey, data):
	try:
		return rsa.decrypt(data,privKey)
	except Exception as e:
		print(e)
		return

def encryptRSA(pubKey, data):
	try:
		return rsa.encrypt(data,pubKey)
	except Exception as e:
		print(e)
		return

def getAESKey():
	return os.urandom(32)

class AESUtils:
	def __init__(self, key):
		self.key = SHA256.new(key).digest()

	def pad(self, s):
	    block_size = 32
	    return  s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)

	def unpad(self, s):
	    if s:
	        return s[:-ord(s[len(s) - 1:])]
	    return

	def encryptAES(self, data):
	    data = self.pad(data)
	    iv = Random.new().read(AES.block_size)
	    cipher = AES.new(self.key, AES.MODE_CBC, iv)
	    return (iv + cipher.encrypt(data)).encode('hex')

	def decryptAES(self, data):
		try:
			data = data.decode('hex')
			iv = data[:AES.block_size]
			cipher = AES.new(self.key, AES.MODE_CBC, iv)
			padded_data = cipher.decrypt(data[AES.block_size:])
			return self.unpad(padded_data)
		except Exception as e:
			print(e)
			return
