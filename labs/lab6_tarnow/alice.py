# Alice
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
alice_pubKey = RSA.importKey(open(os.path.abspath("alicePubKey.pem"), 'r').read())
alice_privKey = RSA.importKey(open(os.path.abspath("aliceKey.pem"), 'r').read())
bob_pubKey = RSA.importKey(open(os.path.abspath("bobPubKey.pem"), 'r').read())

@app.route('/')
def main():
	success = request.cookies.get('success')
	if success is None:
		return render_template("send.html")
	else:
		if success == 'True':
			return render_template("success.html")
		else:
			return render_template("tryagain.html")

@app.route('/send', methods=["POST"])
def send():
	msg = request.form["message"]
	shared_key = sharedKeyGen()
	# encrypt with bob public key (message, shared_key)
	print str(shared_key)
	json_objectInit = {"name" : msg, "sharedKey" : str(shared_key)}
	encrypt_init = bob_pubKey.encrypt(json.dumps(json_objectInit), None)

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
	# encrypted_nonce = data['message']

	# if encrypted_nonce != 'False':
	# 	new_nonceSend = decryptWithSK(shared_key, encrypted_nonce)

	# 	url = 'http://0.0.0.0:8081/bob/nonceSend'
	# 	data = {'message' : new_nonceSend}
	# 	headers = {'Content-type': 'application/json'}
	# 	try:
	# 		nResponse = requests.post(url, data=json.dumps(data), headers=headers)
	# 	except requests.ConnectionError:
	# 		return "Connection Error"
	# 	finalResp = nResponse.text
	# 	data = json.loads(finalResp)
	# 	success = data['message']

	# 	if success == 'True':
	# 		resp = make_response(redirect(url_for("main")))
	# 		resp.set_cookie('success', json.dumps(data['message']), max_age=30)
	# 	else:
	# 		resp = make_response(redirect(url_for("main")))
	# 		resp.set_cookie('success', 'False')
	# else:
	# 	resp = make_response(redirect(url_for("main")))
	# 	resp.set_cookie('success', 'False')
	resp = make_response(redirect(url_for("main")))
	return resp

def decryptWithSK(shared_key, nonce):
	decrypt_nonce = RSA.importKey(shared_key).decrypt(nonce)
	alice_priv = getAliceKey()
	new_msg = "Alice"
	# now need to "sign" or encrypt with Alice's private key
	encrypt_withAlicePriv = RSA.importKey(alice_priv).encrypt(nonce, None)
	json_objectAlice = {"name" : new_msg, "encrypted" : encrypt_withAlicePriv}
	encrypt_recv_nonce = RSA.importKey(shared_key).encrypt(json_objectAlice, None)
	return encrypt_recv_nonce


def readToTxt(keysFile):
	f = open(os.path.abspath(keysFile), 'r')
	pem = f.read()
	return pem

def sharedKeyGen():
	key = RSA.generate(2048)
	f = key.exportKey('PEM')
	return f

def getAlicePubKey():
	f = open('aliceKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def getAliceKey():
	f = open('aliceKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8080, debug = True)