import sys
import logging
import json
import rsa
import base64
import os
from socket import *
from cc_utils import *
from crypto_utils import *
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA256
HOST = "0.0.0.0"
PORT = 8080
MAX_BUFSIZE = 64 * 1024


def connect(host, port):
    try:
        connection = socket(AF_INET, SOCK_STREAM)
        connection.connect((host, port))
    except:
        logging.exception("Couldn't connect\n")
        exit(1)

    print("Connected to " + HOST + ':' + str(PORT) + '\n')
    return connection


def create(sckt, uuid, cert, pubk, pubk_hash, pubk_hash_sig):
    create_msg = dict()
    create_msg['type'] = "create"
    create_msg['uuid'] = base64.b64encode(uuid)
    create_msg['cert'] = cert.as_pem()
    create_msg['pubk'] = pubk
    create_msg['pubk_hash'] = base64.b64encode(pubk_hash)
    create_msg['pubk_hash_sig'] = base64.b64encode(pubk_hash_sig)
    try:
        sckt.sendall(json.dumps(create_msg) + '\r\n')
        data = json.loads(sckt.recv(MAX_BUFSIZE))
        for x in data.values():
            print("id: %s" % x)

    except:
        logging.exception("Couldn't create the box")


def listUsers(sckt):
    list_msg = dict()
    list_msg['type'] = "list"
    try:
        sckt.sendall(json.dumps(list_msg) + '\r\n')

        print("\nList of users with message box:")

        data = json.loads(sckt.recv(MAX_BUFSIZE)).values()
        print(data)

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


def send(sckt, src_id, dst_id, msg, copy, aes_key, signature, msg_digest):
    send = dict()
    send['type'] = "send"
    send['src'] = src_id
    send['dst'] = dst_id
    send['msg'] = msg
    send['copy'] = msg
    send['aes_key'] = base64.b64encode(aes_key)
    send['signature'] = base64.b64encode(signature)
    send['msg_digest'] = base64.b64encode(msg_digest)

    try:
        sckt.sendall(json.dumps(send) + '\r\n')
        print("\nSent message to %s" % dst_id)
        print(sckt.recv(MAX_BUFSIZE))
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
        logging.exception("Couldn't confirm to receipt message")

def recv(sckt, user_id, msg_id):
    receive = dict()
    receive['type'] = "recv"
    receive['id'] = user_id
    receive['msg'] = msg_id

    try:
        sckt.sendall(json.dumps(receive) + '\r\n')
    except:
        logging.exception("Couldn't confirm to receive message")


    own_cert = get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
    print("\nSubject")
    print(own_cert.get_subject())
    privk = rsa.PrivateKey.load_pkcs1(getOwnPrivK(getSerialNumber(own_cert)))
    server_ans = json.loads(sckt.recv(MAX_BUFSIZE))
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

    print("\nSigning the receipt")
    recpt = sign(msg_d, "CITIZEN AUTHENTICATION KEY")

    print("\nSending it to the sender.")
    receipt(sckt, user_id, msg_id, recpt)
    print("Done")

def status(sckt, user_id, msg_id):
    stat_box = dict()
    stat_box['type'] = "status"
    stat_box['id'] = user_id
    stat_box['msg'] = msg_id

    try:
        sckt.sendall(json.dumps(stat_box) + '\r\n')
        print("\nStatus:")
        print(sckt.recv(MAX_BUFSIZE))
    except:
        logging.exception("Couldn't check the reception status")


def getUserDetails(sckt, uid):
    getDetails = dict()
    getDetails['type'] = "userdetails"
    getDetails['uid'] = uid
    try:
        sckt.sendall(json.dumps(getDetails) + '\r\n')
        info = json.loads(sckt.recv(MAX_BUFSIZE))
        cert = info["cert"]
        pubk = info["pubk"]
        pubk_hash = base64.b64decode(info["pubk_hash"])
        pubk_signature = base64.b64decode(info["pubk_signature"])
        #print(pubk_signature)
        print(pubk_hash)
        print("\n---------\n")
        pubk_test_hash = SHA256.new(pubk).hexdigest()
        print(pubk_test_hash)

        if (pubk_test_hash == pubk_hash):
            print("Pub key is not wrong!!!!!!!!!")
        else:
            print("wrong bitch")

        if (verify_signature(pubk_hash, pubk_signature, cert)):
            print("Oi lol")
        else:
            print("shit")

        return {"pubk": pubk, "cert": cert, "pubk_hash": pubk_hash, "pubk_signature": pubk_signature}

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
            with open("%d.txt" % cc_serial_number, 'w') as key_file:
                key_file.write(getAESKey())
            print("\nDone")
            pubk = getOwnPubK(cc_serial_number)
            uuid = cert.get_fingerprint("sha256")
            pubk_hash = SHA256.new(pubk).hexdigest()
            print(pubk_hash)
            print("\nSigning public key...")
            pubk_hash_sig = sign(pubk_hash, "CITIZEN AUTHENTICATION KEY")
            print(pubk_hash_sig)
            print("\nCreating message box...")
            create(sckt, uuid, cert, pubk, pubk_hash, pubk_hash_sig)
            print("Success")
            optionsList(sckt)
        except Exception as e:
            print("\n")
            print(e)
            return
    else:
        optionsList(sckt)


def sendMessage(con):
    src_id = input("\nPlease insert your ID: ")
    dest_id = input("\nPlease insert the receiver ID: ")
    message = raw_input("\nPlease insert your message: ")
    cert = get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
    aes_k = getAESKey()
    aes = AESUtils(aes_k)
    #print(getUserDetails(con, dest_id))
    dest_pk = rsa.PublicKey.load_pkcs1(getUserDetails(con, dest_id)["pubk"])
    msg_digest = SHA256.new(message).hexdigest()
    c_message = aes.encryptAES(message)
    aes_key = encryptRSA(dest_pk, aes_k)
    signature = sign(message, "CITIZEN AUTHENTICATION KEY")
    with open("%d.txt" % getSerialNumber(cert)) as aes_key_file:
        copy_aes_key = aes_key_file.read()
    copy_aes = AESUtils(copy_aes_key)
    copy = copy_aes.encryptAES(message)
    send(con, src_id, dest_id, c_message, copy, aes_key, signature, msg_digest)

def optionsList(con):
    while True:
        print("2. List users with a message box")
        print("3. List the new messages")
        print("4. List all messages")
        print("5. Send a message")
        print("6. Read a message")
        print("8. Checking the reception status of a sent message")
        opt = input("Select an option: ")
        if opt == 2:
            #u_id = input("Please insert the id of the user to be listed: ")
            listUsers(con)
        if opt == 3:
            u_id = input(
                "Please insert the id of the user with the new messages: ")
            listNewMessages(con, u_id)
        if opt == 4:
            u_id = input(
                "Please insert the id of the user to list all messages: ")
            listAllMessages(con, u_id)
        if opt == 5:
            sendMessage(con)
        if opt == 6:
            sender_id = input("\nPlease insert the sender ID: ")
            msg_id = raw_input("\nPlease insert the message ID: ")
            recv(con, sender_id, msg_id)
        if opt == 8:
            u_id = input("Please insert the user id to check the reception: ")
            msg_id = raw_input("Please insert the message identifier: ")
            status(con, u_id, msg_id)


def main():
    con = connect(HOST, PORT)
    login(con)


if __name__ == '__main__':
    main()
