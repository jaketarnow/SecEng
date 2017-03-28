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

app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

@app.route('/sendKey', methods=["POST"])
def sendKey():
	bob_privKey = BobKeyGen()
	bob_pubKey = getBobPubKey()
	
	# send public key to Alice
	url = 'http://0.0.0.0:8080/sendKey'
	data = {'name' : 'Bob', 'PubKey' : bob_pubKey}
	headers = {'Content-type': 'application/json'}
	try:
		uResponse = requests.post(url, data=json.dumps(data), headers=headers)
	except requests.ConnectionError:
		return "Connection Error"
	Jresponse = uResponse.text
	data = json.loads(Jresponse)
	print data['success']

	if data['success'] == True:
		resp = make_response(redirect(url_for("main")))
		resp.set_cookie('userID', 'yup', expires=10)
	else:
		resp = make_response(redirect(url_for("main")))
		resp.set_cookie('userID', 'nope', expires=0)
	return resp

@app.route('/bob/send', methods=['POST'])
def getMessage():
	data = request.get_json()
	sender_name = data['name']
	encrypted_msg = data['message']
	alice_pubkey = data['alicePubKey']
	bob_privKey = BobKeyGen()
	bob_pubKey = getBobPubKey()

	decrypt = RSA.importKey(bob_privKey).encrypt(encrypted_msg, None)
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

@app.route('/bob/send/roundtwo', methods=['POST'])
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

# http://stackoverflow.com/questions/5590170/what-is-the-standard-method-for-generating-a-nonce-in-python
def generate_nonce(length=8):
    # """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def getSharedPubKey(key):
	key = RSA.importKey(key)
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

if __name__ == "__main__":
	#context = (cer, key)
	#app.run(host='0.0.0.0', debug = True, ssl_context=context)
	app.run(host='0.0.0.0', port=8081, debug = True)