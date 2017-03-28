# Charlie
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

app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

def maninmiddle():
	# Grab the stuff and impersonate Alice
	key = CharlieKeyGen()
	return key

@app.route('/charlie/send', methods=['POST'])
def getMessage():
	data = request.get_json()
	sender_name = data['name']
	encrypted_msg = data['message']
	alice_pubkey = data['alicePubKey']
	charlie_privKey = maninmiddle()
	charlie_pubKey = getCharliePubKey()

	decrypt = RSA.importKey(charlie_privKey).encrypt(encrypted_msg, None)
	print decrypt
	print decrypt[0]
	print decrypt[1]
	sharedKey = decrypt[1]
	# generate a random number and encrypt with shared key
	old_nonce = generate_nonce()
	encrypted_noncemsg = RSA.importKey(sharedKey).decrypt(old_nonce)

	url = 'http://0.0.0.0:8080/alice/roundtwo'
	data = {'name' : 'Bob', 'message' : encrypted_noncemsg}
	headers = {'Content-type': 'application/json'}
	try:
		uResponse = requests.post(url, data=json.dumps(data), headers=headers)
	except requests.ConnectionError:
		return "Connection Error"

@app.route('/charlie/send/roundtwo', methods=['POST'])
def getRoundTwo():
	data = request.get_json()
	sender_name = data['name']
	if sender_name == "Alice":
		msg_to_decrypt = data['message']
		decrypt = RSA.importKey(sharedKey).encrypt(msg_to_decrypt, None)
		nonce = RSA.importKey(alice_pubkey).encrypt(decrypt, None)

		if nonce == old_nonce:
			jsonify = {"success" : True}
		else:
			jsonify = {"success" : False}
	url = 'http://0.0.0.0:8080/alice/final'
	data = {'name' : 'Bob', 'message' : jsonify}
	headers = {'Content-type': 'application/json'}
	try:
		uResponse = requests.post(url, data=json.dumps(data), headers=headers)
	except requests.ConnectionError:
		return "Connection Error"


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

def CharlieKeyGen():
	key = RSA.generate(2048)
	f = open('charlieKey.pem', 'w')
	f.write(key.exportKey('PEM'))
	f.close()
	return key

def getCharliePubKey():
	f = open('charlieKey.pem', 'r')
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