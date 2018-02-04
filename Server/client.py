import sys
import logging
import json
import rsa
import base64
import os
import time
from socket import *
from cc_utils import *
from crypto_utils import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from Crypto.Hash import SHA256
HOST = "0.0.0.0"
PORT = 8080
MAX_BUFSIZE = 64 * 1024

shared_secret = ""
private_session_key = ""
checksums = []


def connect(host, port):
    """
    parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
    parameters_to_send = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)
    print(parameters_to_send)
    private_session_key = parameters.generate_private_key()
    public_key = parameters.generate_private_key().public_key()
    to_sign = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    cert = get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
    pkey_signed = sign(to_sign, "CITIZEN AUTHENTICATION KEY")
    print(to_sign)
    connection = dict()
    connection["type"] = "connection"
    connection["pubk"] = base64.b64encode(to_sign)
    connection["cert"] = cert.as_pem()
    connection["pkey_signed"] = base64.b64encode(pkey_signed)
    connection["parameters"] = base64.b64encode(parameters_to_send)
"""
    try:
        con = socket(AF_INET, SOCK_STREAM)
        con.connect((host, port))
        """
        con.sendall(json.dumps(connection) + '\r\n')
        data = json.loads(con.recv(MAX_BUFSIZE))
        print(base64.b64decode(data["pubkey"]))
        server_pubkey = serialization.load_pem_public_key(base64.b64decode(data["pubkey"]), backend=default_backend())
        shared_secret = private_session_key.exchange(server_pubkey)
        print(shared_secret)
        """
    except:
        logging.exception("Couldn't connect\n")
        exit(1)

    print("Connected to " + HOST + ':' + str(PORT) + '\n')
    return con


def create(sckt, uuid, cert, pubk, pubk_hash, pubk_hash_sig, checksum):
    create_msg = dict()
    create_msg['type'] = "create"
    create_msg['uuid'] = base64.b64encode(uuid)
    create_msg['cert'] = cert.as_pem()
    create_msg['pubk'] = pubk
    create_msg['pubk_hash'] = base64.b64encode(pubk_hash)
    create_msg['pubk_hash_sig'] = base64.b64encode(pubk_hash_sig)
    create_msg['checksum'] = base64.b64encode(checksum)
    try:
        sckt.sendall(json.dumps(create_msg) + '\r\n')
        data = json.loads(sckt.recv(MAX_BUFSIZE))
        if checksum == base64.b64decode(data["checksum"]):
            print("Your ID is: %s" % data["result"])
        else:
            print("Error. Bad server response.")
            sys.exit()

    except:
        logging.exception("Couldn't create the box")


def listUsers(sckt):
    list_msg = dict()
    list_msg['type'] = "list"
    try:
        sckt.sendall(json.dumps(list_msg) + '\r\n')

        print("\nList of users with message box:")

        data = json.loads(sckt.recv(MAX_BUFSIZE))
        results = data["result"]
        print("#################USERS LIST#################")
        for key in results.keys():
            user = results[str(key)]
            cert = X509.load_cert_string(user["description"]["cert"])
            name = get_user_name(cert)
            print("ID: %s" % user["id"])
            print("Name: %s" % name)
        print("#################USERS LIST#################")
    except:
        logging.exception("Couldn't list the users")


def listNewMessages(sckt, user_id):
    new_msg = dict()
    new_msg['type'] = "new"
    new_msg['id'] = user_id
    try:
        sckt.sendall(json.dumps(new_msg) + '\r\n')
        print("\nNew messages:")
        data = json.loads(sckt.recv(MAX_BUFSIZE))
        for a in data.values():
            for val in a:
                print(val)
    except:
        logging.exception("Couldn't list the new messages")


def listAllMessages(sckt, user_id):
    all_msg = dict()
    all_msg['type'] = "all"
    all_msg['id'] = user_id
    try:
        sckt.sendall(json.dumps(all_msg) + '\r\n')

        data = json.loads(sckt.recv(MAX_BUFSIZE))
        print("Received messages: ")
        for a in data.values():
            for x in a[0]:
                print(x)

        print("\nSent messages: ")
        for a in data.values():
            for x in a[1]:
                print(x)

    except:
        logging.exception("Couldn't list all messages")


def send(sckt, src_id, dst_id, msg, copy, aes_key, signature, msg_digest, checksum):
    send = dict()
    send['type'] = "send"
    send['src'] = src_id
    send['dst'] = dst_id
    send['msg'] = msg
    send['copy'] = base64.b64encode(copy)
    send['aes_key'] = base64.b64encode(aes_key)
    send['signature'] = base64.b64encode(signature)
    send['msg_digest'] = base64.b64encode(msg_digest)
    send['checksum'] = base64.b64encode(checksum)

    try:
        sckt.sendall(json.dumps(send) + '\r\n')
        data = json.loads(sckt.recv(MAX_BUFSIZE))
        if checksum == base64.b64decode(data["checksum"]):
            print("Sent message to %s" % dst_id)
        else:
            print("Error. Bad server response.")
            sys.exit()
    except:
        logging.exception("Couldn't send message")


def receipt(sckt, own_id, msg_id, receipt):
    recpt = dict()
    recpt['type'] = "receipt"
    recpt['id'] = own_id
    recpt['msg'] = msg_id
    recpt['receipt'] = base64.b64encode(receipt)
    try:
        sckt.sendall(json.dumps(recpt) + '\r\n')
    except:
        logging.exception("Couldn't confirm the receptio of the message.")


def recv(sckt, user_id, msg_id, check):
    receive = dict()
    receive['type'] = "recv"
    receive['id'] = user_id
    receive['msg'] = msg_id
    receive['checksum'] = base64.b64encode(check)

    try:
        sckt.sendall(json.dumps(receive) + '\r\n')
    except:
        logging.exception("Couldn't confirm to receive message")

    own_cert = get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
    privk = rsa.PrivateKey.load_pkcs1(getOwnPrivK(getSerialNumber(own_cert)))
    server_ans = json.loads(sckt.recv(MAX_BUFSIZE))

    if check == base64.b64decode(server_ans["checksum"]):
        server_ans_data = json.loads(server_ans["result"][1])
        sender_uid = server_ans_data["src"]
        cert = getUserDetails(sckt, sender_uid)["cert"]
        aes_key = base64.b64decode(server_ans_data["aes_key"])
        msg_digest = base64.b64decode(server_ans_data["msg_digest"])
        signature = base64.b64decode(server_ans_data["signature"])
        msg = server_ans_data["msg"]

        aes_key_d = decryptRSA(privk, str(aes_key))
        aes = AESUtils(aes_key_d)
        msg_d = aes.decryptAES(msg)

        msg_dige = SHA256.new(msg_d).hexdigest()

        if(msg_dige == msg_digest):
            print("The message was not modified")
        else:
            print("The message was modified. Something is wrong.")
            return

        if not verify_signature(msg_d, signature, cert):
            print("\nSignature not valid")
            return
        else:
            print("\nSignature is valid.")
        print("##################MESSAGE###################")
        print("MESSAGE: %s" % msg_d)
        print("##################MESSAGE###################")

        print("\nSigning the receipt")
        recpt = sign(msg_d, "CITIZEN AUTHENTICATION KEY")

        print("\nSending the receipt to the sender.")
        receipt(sckt, user_id, msg_id, recpt)
        print("Done")
    else:
        print("Error. Bad server response.")
        sys.exit()


def status(sckt, user_id, msg_id, check):
    stat = dict()
    stat['type'] = "status"
    stat['id'] = user_id
    stat['msg'] = msg_id
    stat['checksum'] = base64.b64encode(check)

    try:
        sckt.sendall(json.dumps(stat) + '\r\n')
        info = json.loads(sckt.recv(MAX_BUFSIZE))
        if check == base64.b64decode(info["checksum"]):
            own_cert = get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
            result = info["result"]
            receipts = result["receipts"]
            with open("%s/receipts/%d/%s" % (os.path.dirname(os.path.abspath(__file__)), user_id, msg_id), 'r') as msg_copy:
                msg = msg_copy.read()

            with open("%d.txt" % getSerialNumber(own_cert), 'rb') as key_file:
                aes_key = key_file.read()

            aes = AESUtils(aes_key)
            msg_d = aes.decryptAES(base64.b64decode(msg))


            for rcpt in receipts:
                receipt = base64.b64decode(rcpt["receipt"])
                user = getUserDetails(sckt, rcpt["id"])
                cert = X509.load_cert_string(user["cert"])
                name = get_user_name(cert)
                print("############################################")
                print("Message %s: %s" % (msg_id, msg_d))
                print("Receipt sent by: %s" % name)
                print("Date: %s" % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(rcpt["date"])/1000)))
                if verify_signature(msg_d, receipt, user["cert"]):
                    print("Status: Valid")
                else:
                    print("Status: Invalid")
            print("############################################")
        else:
            print("Error. Bad server response.")
            sys.exit()
    except:
        logging.exception("Error. Something went wrong.")


def getUserDetails(sckt, uid):
    getDetails = dict()
    getDetails['type'] = "userdetails"
    getDetails['uid'] = uid
    getDetails['checksum'] = base64.b64encode(getChecksum())
    try:
        sckt.sendall(json.dumps(getDetails) + '\r\n')
        info = json.loads(sckt.recv(MAX_BUFSIZE))
        if base64.b64decode(getDetails["checksum"]) == base64.b64decode(info["checksum"]):
            cert = info["cert"]
            pubk = info["pubk"]
            pubk_hash = base64.b64decode(info["pubk_hash"])
            pubk_signature = base64.b64decode(info["pubk_signature"])
            pubk_test_hash = SHA256.new(pubk).hexdigest()

            if (pubk_test_hash == pubk_hash):
                pass
            else:
                print("User's public key was modified")
                return

            if (verify_signature(pubk_hash, pubk_signature, cert)):
                pass
            else:
                print("User's could not be validated")
                return

            return {"pubk": pubk, "cert": cert, "pubk_hash": pubk_hash, "pubk_signature": pubk_signature}
        else:
            print("Bad server response. Quitting.")
            sys.exit()


    except Exception as e:
        print(e)
        return


def getOwnPubK(cc_serial_number):
    try:
        with open("%d.pub" % cc_serial_number) as pubk_file:
            return pubk_file.read()
    except:
        return


def getOwnPrivK(cc_serial_number):
    try:
        with open("%d.priv" % cc_serial_number) as privk_file:
            return privk_file.read()
    except:
        return


def login(con):
    sckt = con
    cert = get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
    cc_serial_number = getSerialNumber(cert)
    if not os.path.isfile("%d.pub" % cc_serial_number):
        try:
            print("\nGenerating pair of RSA keys...")
            generateKeys(4096, str(cc_serial_number))
            print("\nDone.")
            print("\nGenerating AES key...")
            key = getAESKey()
            with open("%d.txt" % cc_serial_number, 'w') as key_file:
                key_file.write(key)
            print("\nDone")
            pubk = getOwnPubK(cc_serial_number)
            uuid = cert.get_fingerprint("sha256")
            pubk_hash = SHA256.new(pubk).hexdigest()
            print("\nSigning public key...")
            pubk_hash_sig = sign(pubk_hash, "CITIZEN AUTHENTICATION KEY")
            print("\nCreating message box...")
            check = getChecksum()
            create(sckt, uuid, cert, pubk, pubk_hash, pubk_hash_sig, check)
            print("Success")
            optionsList(sckt)
        except Exception as e:
            print("\n")
            print(e)
            return
    else:
        optionsList(sckt)

def getChecksum():
    rand = os.urandom(16)
    checksum = SHA256.new(rand).hexdigest()
    if checksum not in checksums:
        checksums.append(checksum)
        return checksum
    else:
        getChecksum()

def sendMessage(con):
    src_id = input("\nPlease insert your ID: ")
    dest_id = input("\nPlease insert the receiver ID: ")
    message = raw_input("\nPlease insert your message: ")
    cert = get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
    aes_k = getAESKey()
    aes = AESUtils(aes_k)
    dest_pk = rsa.PublicKey.load_pkcs1(getUserDetails(con, dest_id)["pubk"])
    msg_digest = SHA256.new(message).hexdigest()
    c_message = aes.encryptAES(message)
    aes_key = encryptRSA(dest_pk, aes_k)
    signature = sign(message, "CITIZEN AUTHENTICATION KEY")
    with open("%d.txt" % getSerialNumber(cert), 'r') as aes_key_file:
        copy_aes_key = aes_key_file.read()
    copy_aes = AESUtils(copy_aes_key)
    copy = copy_aes.encryptAES(message)
    check = getChecksum()
    send(con, src_id, dest_id, c_message, copy, aes_key, signature, msg_digest, check)

def optionsList(con):
    while True:
        print("\n--------------------------------MENU-----------------------------")
        print("1. List users")
        print("2. New messages")
        print("3. List all messages")
        print("4. Send a message")
        print("5. Read a message")
        print("6. Sent messages status")
        print("-----------------------------------------------------------------")
        opt = input("Select an option: ")
        if opt == 1:
            listUsers(con)
        if opt == 2:
            u_id = input(
                "Please insert the id of the user with the new messages: ")
            listNewMessages(con, u_id)
        if opt == 3:
            u_id = input(
                "Please insert the id of the user to list all messages: ")
            listAllMessages(con, u_id)
        if opt == 4:
            sendMessage(con)
        if opt == 5:
            sender_id = input("\nPlease insert the sender ID: ")
            msg_id = raw_input("\nPlease insert the message ID: ")
            checksum = getChecksum()
            recv(con, sender_id, msg_id, checksum)
        if opt == 6:
            u_id = input("Please insert the user id to check the reception: ")
            msg_id = raw_input("Please insert the message identifier: ")
            checksum = getChecksum()
            status(con, u_id, msg_id, checksum)


def main():
    con = connect(HOST, PORT)
    login(con)

if __name__ == '__main__':
    main()
