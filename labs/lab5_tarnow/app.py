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
	user_id = request.cookies.get('userID')

	if user_id != None:
		if user_id == 'nope':
			return render_template("nameindex.html")
		else:
			url = 'http://0.0.0.0:8081/api/userInfo'
			data = {'user_cookie' : user_id}
			headers = {'Content-type': 'application/json'}

			try:
				uResponse = requests.post(url, data=json.dumps(data), headers=headers)
			except requests.ConnectionError:
				return "Connection Error"
			Jresponse = uResponse.text
			data = json.loads(Jresponse)
			if data['success'] == True:
				return render_template("index.html")
			else:
				return render_template("signupfail.html")
	else:
		return render_template("signup.html")

@app.route('/signup', methods=["POST"])
def signup():
	username_form = request.form["username"]
	password_form = request.form["password"]
	password_form = hashIt(password_form)
	pub_key = request.form["pubkey"]
	newpubkey = readToTxt(pub_key)

	# now send to data server!
	url = 'http://0.0.0.0:8081/api/signup'
	data = {'username' : username_form, 'password' : password_form, 'key' : newpubkey}
	headers = {'Content-type': 'application/json'}
	try:
		uResponse = requests.post(url, data=json.dumps(data), headers=headers)
	except requests.ConnectionError:
		return "Connection Error"
	Jresponse = uResponse.text
	data = json.loads(Jresponse)

	if data['success'] == True:
		editHTML(username_form)
		cookie_toset = data['cookie']
		resp = make_response(redirect(url_for("main")))
		resp.set_cookie('userID', json.dumps(cookie_toset), max_age=30)
	else:
		resp = make_response(redirect(url_for("main")))
		resp.set_cookie('userID', 'nope')
	return resp

@app.route('/login', methods=["GET", "POST"])
def login():
	if request.method == "POST":
		username_form = request.form["username"]
		password_form = request.form["password"]
		key = request.form["key"]
		newkey = readToTxt(key)
		# Decrypt with private key, then encrypt with public key
		hashedPwd = RSA.importKey(newkey).decrypt(hashIt(password_form))
		# encode hashedPwd with base64 to preserve hash
		url = 'http://0.0.0.0:8081/api/login'
		jData = {'username' : username_form, 'crypto' : base64.b64encode(hashedPwd)}
		headers = {'Content-type': 'application/json'}
		try:
			# build request with data as json object
			uResponse = requests.post(url, data=json.dumps(jData), headers=headers)
		except requests.ConnectionError:
			return "Connection Error"
		Jresponse = uResponse.text
		data = json.loads(Jresponse)

		if data['success'] == True:
			editHTML(username_form)
			resp = make_response(redirect(url_for("main")))
			resp.set_cookie('userID', json.dumps(data['cookie']), max_age=30)
		return resp
	return render_template("login.html")

def editHTML(user_name):
	with open("templates/index.html") as inf:
		txt = inf.read()
		soup = bs4.BeautifulSoup(txt)
	# create new elem
	var = 'I have your identity ' + user_name.title() + ' !!!'
	for i in soup.find_all(class_='test'):
		i.string = var
	# save file again
	with open("templates/index.html", "w") as outf:
		outf.write(str(soup))


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

@app.route('/logout')
def logout():
	editHTML(" ")
	resp = make_response(redirect(url_for("main")))
	resp.set_cookie('userID', expires=0)
	return resp

if __name__ == "__main__":
	#context = (cer, key)
	#app.run(host='0.0.0.0', debug = True, ssl_context=context)
	app.run(host='0.0.0.0', port=8080, debug = True)