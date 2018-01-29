import rsa
import os
import sys

def generateKeys(keySize=4096, keyName='key', path=os.getcwd()):
	pub = open(path+'/'+keyName+'.pub','wb')
	priv = open(path+'/'+keyName+'.priv','wb')
	(pubkey, privkey) = rsa.newkeys(keySize,poolsize=2)
	pub.write(pubkey.save_pkcs1())
	priv.write(privkey.save_pkcs1())
	pub.close()
	priv.close()
