import rsa
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

def pad(s):
    block_size = 16
    return  s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)

def unpad(s):
    if s:
        return s[:-ord(s[len(s) - 1:])]
    return

def encryptAES(self, data):
    key = SHA256.new(key.encode()).hexdigest()
    data = pad(data)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(data))

 def decryptAES(self, data):
    data = b64decode(data)
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(data[AES.block_size:])
    return unpad(padded_data)
