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

@app.route('/')
def main():
	return render_template("index.html")

@app.route('/sendKey', methods=["POST"])
def getBobKey():
	data = request.get_json()
	if data['name'] == "Bob":
		bobPubKey = data['PubKey']

	url = 'http://0.0.0.0:8080/send'
	data = {'name' : 'Bob', 'PubKey' : bobPubKey}
	headers = {'Content-type': 'application/json'}
	try:
		uResponse = requests.post(url, data=json.dumps(data), headers=headers)
	except requests.ConnectionError:
		return "Connection Error"

@app.route('/send', methods=["POST"])
def send():
	data = request.get_json()
	if data['name'] == "Bob":
		bob_pubKey = data['PubKey']

	alice_privKey = AliceKeyGen()
	alice_pubKey = getAlicePubKey()
	# create new shared key for bob and alice
	shared_key = sharedKeyGen()
	message = "Alice"
	# encrypt it
	encryptedMessage = RSA.importKey(bob_pubKey).decrypt(message, shared_key)

	# now send to Bob
	url = 'http://0.0.0.0:8081/bob/send'
	data = {'name' : 'Alice', 'message' : encryptedMessage, 'alicePubKey' : alice_pubKey}
	headers = {'Content-type': 'application/json'}
	try:
		uResponse = requests.post(url, data=json.dumps(data), headers=headers)
	except requests.ConnectionError:
		return "Connection Error"

	Jresponse = uResponse.text
	data = json.loads(Jresponse)
	print data['bobResponse']
	print data['success']

	if data['success'] == True:
		resp = make_response(redirect(url_for("main")))
		resp.set_cookie('userID', 'yup', expires=10)
	else:
		resp = make_response(redirect(url_for("main")))
		resp.set_cookie('userID', 'nope', expires=0)
	return resp

@app.route('/alice/roundtwo', methods=["POST"])
def roundtwo():
	data = request.get_json()
	if data['name'] == "Bob":
		msg = data['message']
		shared_key = getSharedPubKey()
		nonce = RSA.importKey(shared_key).encrypt(msg, None)
		shared_keyAll = getsharedKey()
		# Once Alice has decrypted this, she then sends new message
		alice_privKey = getAliceKey()
		encryptedNonce = RSA.importKey(alice_privKey).decrypt(nonce)
		messageToSendWithSharedKey = RSA.importKey(shared_key).decrypt(encryptedNonce, shared_keyAll)

		# now send to Bob
		url = 'http://0.0.0.0:8081/bob/send/roundtwo'
		data = {'name' : 'Alice', 'message' : messageToSendWithSharedKey}
		headers = {'Content-type': 'application/json'}
		try:
			uResponse = requests.post(url, data=json.dumps(data), headers=headers)
		except requests.ConnectionError:
			return "Connection Error"

@app.route('/alice/final', methods=["POST"])
def getAnswer():
	data = request.get_json()
	if data['name'] == "Bob":
		answer = data['message']
		if answer['success'] == True:
			return True
		else:
			return False

# http://stackoverflow.com/questions/5590170/what-is-the-standard-method-for-generating-a-nonce-in-python
def generate_nonce(length=8):
    # """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def sharedKeyGen():
	key = RSA.generate(2048)
	f = open('sharedKey.pem', 'w')
	f.write(key.exportKey('PEM'))
	f.close()
	return key

def getsharedKey():
	f = open('sharedKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key

def getSharedPubKey():
	f = open('sharedKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def AliceKeyGen():
	key = RSA.generate(2048)
	f = open('aliceKey.pem', 'w')
	f.write(key.exportKey('PEM'))
	f.close()
	return key

def getAlicePubKey():
	f = open('aliceKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def getAliceKey():
	f = open('aliceKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key

def readToTxt(keysFile):
	f = open(os.path.abspath(keysFile), 'r')
	pem = f.read()
	return pem

if __name__ == "__main__":
	#context = (cer, key)
	#app.run(host='0.0.0.0', debug = True, ssl_context=context)
	app.run(host='0.0.0.0', port=8080, debug = True)