import sys
import logging
import json
from socket import *
HOST = "0.0.0.0"
PORT = 8080

def connect(host, port):
    try:
        connection = socket(AF_INET, SOCK_STREAM)
        connection.connect((host, port))
    except:
        logging.exception("Couldn't connect\n")
        exit(1)

    print("Connected to " + HOST + ':' + str(PORT) + '\n')
    return connection

def createBox(sckt, uuid):
    create_msg = dict()
    create_msg['type'] = "create"
    create_msg['uuid'] = uuid
    try:
        sckt.sendall(json.dumps(create_msg)+'\r\n')
    except:
        logging.exception("Couldn't create the box")
    print("Box created successfully!")

def listBox(sckt, user_id):
    list_msg = dict()
    list_msg['type'] = "list"
    list_msg['id'] = user_id
    try:
        sckt.sendall(json.dumps(list_msg)+'\r\n')
    except:
        logging.exception("Couldn't list the users")

def main():
    con = connect(HOST, PORT)
    while True:
        print("1. Create message box\n")
        print("2. List users with a message box\n")
        opt = input("Select an option: \n")
        if opt == 1:
            uuid = input("Please insert your ID: ")
            createBox(con, uuid)
        if opt == 2:
            u_id = input("Please insert the id of the user to be listed: ")
            listBox(con, u_id)


if __name__ == '__main__':
    main()
