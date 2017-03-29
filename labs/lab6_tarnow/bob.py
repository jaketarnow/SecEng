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
import random

app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

# http://stackoverflow.com/questions/5590170/what-is-the-standard-method-for-generating-a-nonce-in-python
def generate_nonce(length=8):
    # """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

nonce = generate_nonce()
shared_key = None

alice_pubKey = RSA.importKey(open(os.path.abspath("alicePubKey.pem"), 'r').read())
bob_pubKey = RSA.importKey(open(os.path.abspath("bobPubKey.pem"), 'r').read())
bob_privKey = RSA.importKey(open(os.path.abspath("bobKey.pem"), 'r').read())

@app.route('/bob/send', methods=['GET', 'POST'])
def send():
	data = request.get_json()
	encrypt_init = data['message']
	encrypt_init = base64.b64decode(encrypt_init)
	decrypt_init = bob_privKey.decrypt(encrypt_init)
	print decrypt_init
	# name = json_decrypt_init['name']
	# shared_key = json_decrypt_init['sharedKey']

	# if msg == 'Alice':
	# 	nonce = generate_nonce()
	# 	encrypted_nonce = RSA.importKey(shared_key).encrypt(nonce, None)
	# 	jsonify = {'message': encrypted_nonce[0]}
	# else:
	jsonify = {'message': 'False'}
	return json.dumps(jsonify, indent=4)


@app.route('/bob/nonceSend', methods=['GET', 'POST'])
def nonceSend():
	data = request.get_json()
	encrypt_nonce = data['message']
	decrypt_init = RSA.importKey(shared_key).decrypt(encrypt_nonce)
	msg = decrypt_init[0]
	alice_encrypt_none = decrypt_init[1]

	if msg == 'Alice':
		alice_pubKey = getAlicePubKey()
		decrypt_nonce = RSA.importKey(alice_pubKey).decrypt(alice_encrypt_none)
		new_nonce = decrypt_nonce[0]
		# if new_nonce is same as nonce that Bob created, then send success!
		if new_nonce == nonce:
			jsonify = {'message': 'True'}
		else:
			jsonify = {'message': 'False'}
	else:
		jsonify = {'message': 'False'}
	return json.dumps(jsonify, indent=4)

def readToTxt(keysFile):
	f = open(str(keysFile), 'r')
	pem = f.read()
	return pem

def getBobPubKey():
	f = open('bobPubKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def getAlicePubKey():
	f = open('aliceKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def getBobKey():
	f = open('bobKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8081, debug = True)