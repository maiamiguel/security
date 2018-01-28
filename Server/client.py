import sys
import logging
import json
import hashlib
import base64
import pickle
from socket import *
from cc_utils import *
from cryptography.hazmat.primitives import hashes
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


def createBox(sckt, uuid, cert, signature):
    create_msg = dict()
    create_msg['type'] = "create"
    create_msg['uuid'] = base64.b64encode(uuid)
    create_msg['cert'] = cert.as_pem()
    create_msg['signature'] = base64.b64encode(signature)
    try:
        sckt.sendall(json.dumps(create_msg) + '\r\n')
        data = json.loads(sckt.recv(MAX_BUFSIZE))
        for x in data.values():
            print("id: %s" % x)

    except:
        logging.exception("Couldn't create the box")


def listBox(sckt):
    list_msg = dict()
    list_msg['type'] = "list"
    try:
        sckt.sendall(json.dumps(list_msg) + '\r\n')

        print("\nList of users with message box:")

        data = json.loads(sckt.recv(MAX_BUFSIZE)).values()
        for x in data:
            for i in x:
                print(i["uuid"])

    except:
        logging.exception("Couldn't list the users")


def newBox(sckt, user_id):
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


def allBox(sckt, user_id):
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


def sendBox(sckt, src_id, dst_id, msg):
    send_box = dict()
    send_box['type'] = "send"
    send_box['src'] = src_id
    send_box['dst'] = dst_id
    send_box['msg'] = msg
    send_box['copy'] = msg

    try:
        sckt.sendall(json.dumps(send_box) + '\r\n')
        print("\nSent message to %s" % dst_id)
        print(sckt.recv(MAX_BUFSIZE))
    except:
        logging.exception("Couldn't send message")


def recvBox(sckt, user_id, msg_id):
    recv_box = dict()
    recv_box['type'] = "recv"
    recv_box['id'] = user_id
    recv_box['msg'] = msg_id

    try:
        sckt.sendall(json.dumps(recv_box) + '\r\n')
        print(sckt.recv(MAX_BUFSIZE))
    except:
        logging.exception("Couldn't confirm to receive message")


def receiptBox(sckt, user_id, msg_id, receipt):
    receipt_box = dict()
    receipt_box['type'] = "receipt"
    receipt_box['id'] = user_id
    receipt_box['msg'] = msg_id
    receipt_box['receipt'] = receipt

    try:
        sckt.sendall(json.dumps(receipt_box) + '\r\n')
        print(sckt.recv(MAX_BUFSIZE))
    except:
        logging.exception("Couldn't confirm to receipt message")


def statusBox(sckt, user_id, msg_id):
    stat_box = dict()
    stat_box['type'] = "status"
    stat_box['id'] = user_id
    stat_box['msg'] = msg_id

    try:
        sckt.sendall(json.dumps(stat_box) + '\r\n')
        print("\nStatus:")
        print(sckt.recv(MAX_BUFSIZE))
    except:
        logging.exception("Couldn't checking the reception status")


def register(con):
    sckt = con
    cert = get_certificate("CITIZEN AUTHENTICATION CERTIFICATE")
    uuid = cert.get_fingerprint("sha256")
    signature = sign(uuid, "CITIZEN AUTHENTICATION KEY")

    createBox(sckt, uuid, cert, signature)

def options_list():
    while True:
        print("\n1. Create message box")
        print("2. List users with a message box")
        print("3. List the new messages")
        print("4. List all messages")
        print("5. Client send a message to a user's message box")
        print("6. Client confirm to receive a message from a users message box")
        print("7. Receipt messages")
        print("8. Checking the reception status of a sent message")
        opt = input("Select an option: ")
        if opt == 1:
            uuid = input("Please insert your ID: ")
            createBox(con, uuid)
        if opt == 2:
            #u_id = input("Please insert the id of the user to be listed: ")
            listBox(con)
        if opt == 3:
            u_id = input(
                "Please insert the id of the user with the new messages: ")
            newBox(con, u_id)
        if opt == 4:
            u_id = input(
                "Please insert the id of the user to list all messages: ")
            allBox(con, u_id)
        if opt == 5:
            u_send = input("Please insert the id of the sender: ")
            u_dst = input("Please insert the id of the receiver: ")
            u_msg = raw_input("Please insert the message: ")
            sendBox(con, u_send, u_dst, u_msg)
        if opt == 6:
            u_id = input(
                "Please insert the id of the user to confirm the message: ")
            msgid = raw_input("Please insert the message id: ")
            recvBox(con, u_id, msgid)
        if opt == 7:
            u_id = input("Please insert the id of the receipt sender: ")
            msgid = raw_input(
                "Please insert the identifier of message of the receipt sender: ")
            recpt = raw_input("Please insert msg: ")
            receiptBox(con, u_id, msgid, recpt)
        if opt == 8:
            u_id = input("Please insert the user id to check the reception: ")
            msg_id = raw_input("Please insert the message identifier: ")
            statusBox(con, u_id, msg_id)


def login(con):
    while True:
        print("1. Login\n")
        print("2. New User\n")
        opt = input("Select an option: \n")
        if opt == 1:
            # cenas
            options_list()
        if opt == 2:
            register(con)


def main():
    con = connect(HOST, PORT)
    login(con)


if __name__ == '__main__':
    main()
