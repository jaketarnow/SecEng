# Alice
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
alice_pubKey = RSA.importKey(open(os.path.abspath("alicePubKey.pem"), 'r').read())
alice_privKey = RSA.importKey(open(os.path.abspath("aliceKey.pem"), 'r').read())
bob_pubKey = RSA.importKey(open(os.path.abspath("bobPubKey.pem"), 'r').read())

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

@app.route('/send', methods=["POST"])
def send():
	msg = request.form["message"]     
	shared_key = sharedKeyGen()     
	json_objectInit = json.dumps({"name" : str(msg), "sharedKey" : shared_key})
	encrypt_init = bob_pubKey.encrypt(json_objectInit, None)
	# decrypt_init = alice_privKey.decrypt(encrypt_init[0])
	# decrypt_init = json.loads(decrypt_init)
	# print decrypt_init

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
		new_nonceSend = decrypt_aes(encrypted_nonce, shared_key)
		print new_nonceSend
		print str(new_nonceSend)
		signed = alice_privKey.sign(str(new_nonceSend), None)
		json_objectInit = json.dumps({"name" : str(msg), "newNonce" : signed[0]})
		encrypted_new_nonceSend = encrypt_aes(json_objectInit, shared_key)

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
		print success

		if success:
			print "IN FINAL 1st IF"
			resp = make_response(redirect(url_for("main")))
			resp.set_cookie('success', json.dumps(data['message']), max_age=30)
		else:
			print "IN FINAL 1st ELSE"
			resp = make_response(redirect(url_for("main")))
			resp.set_cookie('success', 'False')
	else:
		print "IN FINAL 2nd ELSE"
		resp = make_response(redirect(url_for("main")))
		resp.set_cookie('success', 'False')
	return resp

def readToTxt(keysFile):
	f = open(os.path.abspath(keysFile), 'r')
	pem = f.read()
	return pem

def sharedKeyGen():
	# create something similar to 
	n = 16
	return "".join(choice(lowercase) for i in range(n))

def getAlicePubKey():
	f = open('aliceKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def getAliceKey():
	f = open('aliceKey.pem', 'r')
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
	app.run(host='0.0.0.0', port=8080, debug = True)