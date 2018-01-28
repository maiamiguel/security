import PyKCS11
import M2Crypto
import sys
from M2Crypto import X509

path = "/usr/local/lib/libpteidpkcs11.so"

def get_certificate(label):
    flag    = False
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(path)

    try:
        slots = pkcs11.getSlotList()
    except:
        print("Couldn't detect a card reader.")
        sys.exit(0)
    try:
        session = pkcs11.openSession(slots[0])
    except:
        print("Couldn't read the card.")
        sys.exit(0)

    objs = session.findObjects(template=((PyKCS11.CKA_LABEL, label),
                                         (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)))
    try:
        der = ''.join(chr(c) for c in objs[0].to_dict()['CKA_VALUE'])
    except:
        flag = True
    if flag:
        return None
    session.closeSession()
    return X509.load_cert_string(der, X509.FORMAT_DER)

def sign(data, label):
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(path)
    slots = pkcs11.getSlotList()
    session = pkcs11.openSession(slots[0])
    key = session.findObjects(template=((PyKCS11.CKA_LABEL, label),
                                          (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                          (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA) ))[0]
    mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
    try:
        sig = session.sign(key, data,mech)
    except:
        print("Couldn't sign data.")
        return None
    ret = ''.join(chr(c) for c in sig)
    return ret

def verify_signature(original, signed, cert_str):
    cert = X509.load_cert_string(cert_str)
    pkey = cert.get_pubkey()
    pkey.verify_init()
    pkey.verify_update(original)
    return pkey.verify_final(signed)
