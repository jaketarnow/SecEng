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

#context = SSL.Context(SSL.SSLv23_METHOD)
#cer = os.path.join(os.path.dirname(__file__), 'certificate.crt')
#key = os.path.join(os.path.dirname(__file__), 'privateKey.key')
app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

@app.route('/')
def main():
	return render_template("index.html")

@app.route('/send', methods=["POST"])
def send():
	message = request.form["message"]
	alice_privKey = AliceKeyGen()
	alice_pubKey = getAlicePubKey()
	# encrypt it
	encryptedMessage = RSA.importKey(alice_pubKey).decrypt(message)
	# create new shared key for bob and alice
	shared_key = sharedKeyGen()


	# now send to Bob
	url = 'http://0.0.0.0:8081/bob/send'
	data = {'name' : 'Alice', 'message' : encryptedMessage, 'sharedKey' : shared_key, 'AlicePubKey' : alice_pubKey}
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
	app.run(host='0.0.0.0', port=8080, debug = True)