import rsa

def verifySig(pubKey,signature,data):
    pubKey = rsa.PublicKey.load_pcks11(pubKey)
    return rsa.verify(data,signature,pubKey)
