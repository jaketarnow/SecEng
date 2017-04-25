# Bob
from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response, jsonify
from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
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
	# make into session variable instead of global!!
	global shared_key
	global nonce
	data = request.get_data()
	encrypt_init = json.loads(data)
	encrypt_init = encrypt_init['message']
	encrypt_init = base64.b64decode(encrypt_init)

	decrypt_init = bob_privKey.decrypt(encrypt_init)
	json_decrypt_init = json.loads(decrypt_init)
	msg = json_decrypt_init['name']
	shared_key = json_decrypt_init['sharedKey']

	if msg is not None:
		nonce = generate_nonce()
		print nonce
		encrypted_nonce = encrypt_aes(nonce, shared_key)
		print encrypted_nonce
		jsonify = {'message': encrypted_nonce}
	else:
		jsonify = {'message': 'False'}
	return json.dumps(jsonify, indent=4)


@app.route('/bob/nonceSend', methods=['GET', 'POST'])
def nonceSend():
	global shared_key
	global nonce
	data = request.get_data()
	encrypt_nonce = json.loads(data)
	encrypt_nonce = encrypt_nonce['message']
	decrypt_init = decrypt_aes(encrypt_nonce, shared_key)
	print decrypt_init
	decrypt_init = json.loads(decrypt_init)

	# public key lookup of key based on the name

	msg = decrypt_init['name']
	print msg
	new_nonce = decrypt_init['newNonce']
	print new_nonce
	# use msg as key for lookup of public key
	if msg is not None:
		alice_pubKey = getAlicePubKey()
		new_nonce = (long(new_nonce),)
		decrypt_nonce = alice_pubKey.verify(nonce, new_nonce)
		print decrypt_nonce
		# if new_nonce is same as nonce that Bob created, then send success!
		if decrypt_nonce:
			jsonify = {'message': True}
		else:
			jsonify = {'message': False}
	else:
		jsonify = {'message': False}
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

# http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
def encrypt_aes(message, passphrase):
	IV = Random.new().read(AES.block_size)
	aes = AES.new(passphrase, AES.MODE_CFB, IV)
	return base64.b64encode(IV + aes.encrypt(message))

# http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
def decrypt_aes(encrypted, passphrase):
	new_encrypted = base64.b64decode(encrypted)
	IV = new_encrypted[:AES.block_size]
	aes = AES.new(passphrase, AES.MODE_CFB, IV)
	return aes.decrypt(new_encrypted[AES.block_size:]).decode('utf-8')

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8081, debug = True)