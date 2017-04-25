# Charlie
from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response, jsonify
from OpenSSL import SSL
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from random import choice
from string import lowercase
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
import sys
import random
import string

app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

# http://stackoverflow.com/questions/5590170/what-is-the-standard-method-for-generating-a-nonce-in-python
def generate_nonce(length=8):
    # """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

nonce = generate_nonce()
shared_key_withAlice = None
new_sharedKey_withBob = None

alice_pubKey = RSA.importKey(open(os.path.abspath("alicePubKey.pem"), 'r').read())
bob_pubKey = RSA.importKey(open(os.path.abspath("bobPubKey.pem"), 'r').read())
charlie_pubKey = RSA.importKey(open(os.path.abspath("charliePubKey.pem"), 'r').read())
charlie_privKey = RSA.importKey(open(os.path.abspath("charlieKey.pem"), 'r').read())

@app.route('/')
def main():
	success = request.cookies.get('success')
	print "IN MAIN!!"
	print success
	if success is None:
		return render_template("send.html")
	else:
		if success:
			return render_template("success.html")
		else:
			return render_template("tryagain.html")

@app.route('/charlie/send', methods=['GET', 'POST'])
def send():
	global shared_key_withAlice
	global new_sharedKey_withBob
	global nonce
	data = request.get_data()
	encrypt_init = json.loads(data)
	encrypt_init = encrypt_init['message']
	encrypt_init = base64.b64decode(encrypt_init)

	decrypt_init = charlie_privKey.decrypt(encrypt_init)
	json_decrypt_init = json.loads(decrypt_init)
	msg = json_decrypt_init['name']
	shared_key_withAlice = json_decrypt_init['sharedKey']

	if msg is not None:
		new_sharedKey_withBob = sharedKeyGen()
		# sends bob new shared key
		json_objectInit = json.dumps({"name" : str(msg), "sharedKey" : new_sharedKey_withBob})
		encrypt_init = bob_pubKey.encrypt(json_objectInit, None)

		url = 'http://0.0.0.0:8081/bob/send'
		data = {'message' : base64.b64encode(encrypt_init[0])}
		headers = {'Content-type': 'application/json'}

		try:
			uResponse = requests.post(url, data=json.dumps(data), headers=headers)
		except requests.ConnectionError:
			return "Connection Error"
		Jresponse = uResponse.text
		data = json.loads(Jresponse)
		print data
		encrypted_nonce = data['message']
		print encrypted_nonce

		if encrypted_nonce != 'False':
			new_nonceSend = decrypt_aes(encrypted_nonce, new_sharedKey_withBob)
			charlie_encrypted_nonce = encrypt_aes(new_nonceSend, shared_key_withAlice)
			jsonify = {'message': charlie_encrypted_nonce}
		else:
			jsonify = {'message': 'False'}
	else:
		jsonify = {'message': 'False'}
	return json.dumps(jsonify, indent=4)

@app.route('/charlie/nonceSend', methods=['GET', 'POST'])
def nonceSend():
	global shared_key_withAlice
	global new_sharedKey_withBob
	global nonce
	data = request.get_data()
	encrypt_nonce = json.loads(data)
	encrypt_nonce = encrypt_nonce['message']
	decrypt_init = decrypt_aes(encrypt_nonce, shared_key_withAlice)
	print decrypt_init
	decrypt_init = json.loads(decrypt_init)
	msg = decrypt_init['name']
	print msg
	new_nonce = decrypt_init['newNonce']
	print new_nonce

	if msg is not None:
		# charlie encrypts with shared key of bob and signature
		json_objectInit = json.dumps({"name" : str(msg), "newNonce" : new_nonce})
		encrypted_new_nonceSend = encrypt_aes(json_objectInit, new_sharedKey_withBob)

		url = 'http://0.0.0.0:8081/bob/nonceSend'
		data = {'message' : encrypted_new_nonceSend}
		headers = {'Content-type': 'application/json'}
		try:
			nResponse = requests.post(url, data=json.dumps(data), headers=headers)
		except requests.ConnectionError:
			return "Connection Error"
		finalResp = nResponse.text
		data = json.loads(finalResp)
		success = data['message']

		if success:
			jsonify = {'message': True}
		else:
			jsonify = {'message': False}
	else:
		jsonify = {'message': False}
	return json.dumps(jsonify, indent=4)

def readToTxt(keysFile):
	f = open(os.path.abspath(keysFile), 'r')
	pem = f.read()
	return pem

def sharedKeyGen():
	# create something similar to 
	n = 16
	return "".join(choice(lowercase) for i in range(n))

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
	app.run(host='0.0.0.0', port=8082, debug = True)