# Bob
from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response, jsonify
from OpenSSL import SSL
from Crypto.PublicKey import RSA
import hashlib
import base64
import os
import Cookie
import datetime
import json
import requests
import codecs
import bs4
import re

#context = SSL.Context(SSL.SSLv23_METHOD)
#cer = os.path.join(os.path.dirname(__file__), 'certificate.crt')
#key = os.path.join(os.path.dirname(__file__), 'privateKey.key')
app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

@app.route('/bob/send', methods=['POST'])
def getMessage():
	data = request.get_json()
	sender_name = data['name']
	encrypted_msg = data['message']
	shared_key = data['sharedKey']
	alice_pubkey = data['alicePubKey']

	bob_privKey = 
	bob_pubKey = 

	decrypt = RSA.importKey().encrypt(encryptedHash, None)




def sharedKeyGen():
	key = RSA.generate(2048)
	f = open('sharedKey.pem', 'w')
	f.write(key.exportKey('PEM'))
	f.close()
	return key

def getSharedPubKey():
	f = open('sharedKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def BobKeyGen():
	key = RSA.generate(2048)
	f = open('bobKey.pem', 'w')
	f.write(key.exportKey('PEM'))
	f.close()
	return key

def getBobPubKey():
	f = open('bobKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def readToTxt(keysFile):
	f = open(os.path.abspath(keysFile), 'r')
	pem = f.read()
	return pem

def writeToFile(encrypted):
	f = open('encrypt.txt', 'w')
	f.write(encrypted)
	f.close()

def hashIt(hashme):
	hashed = hashme
	hash_object = hashlib.sha256(hashed)
	hex_dig = hash_object.hexdigest()
	hashed = hex_dig
	return hashed

if __name__ == "__main__":
	#context = (cer, key)
	#app.run(host='0.0.0.0', debug = True, ssl_context=context)
	app.run(host='0.0.0.0', port=8081, debug = True)