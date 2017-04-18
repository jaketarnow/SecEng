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
		elif user_id == 'Welcome':
			return render_template("index.html")
	else:
		return render_template("login.html")

@app.route('/login', methods=["GET", "POST"])
def login():
	if request.method == "POST":
		username_form = request.form["username"]
		password_form = request.form["password"]

		url = 'http://0.0.0.0:8081/api/login'
		jData = {'username' : username_form, 'password' : password_form}
		headers = {'Content-type': 'application/json'}
		try:
			# build request with data as json object
			uResponse = requests.post(url, data=json.dumps(jData), headers=headers)
		except requests.ConnectionError:
			return "Connection Error"
		Jresponse = uResponse.text
		data = json.loads(Jresponse)

		if data['success'] == True:
			editHTML(data['answer'])
			resp = make_response(redirect(url_for("main")))
			resp.set_cookie('userID', 'Welcome', max_age=30)
		return resp
	return render_template("login.html")

def editHTML(user_name):
	with open("templates/index.html") as inf:
		txt = inf.read()
		soup = bs4.BeautifulSoup(txt)
	# create new elem
	var = user_name.title()
	for i in soup.find_all(class_='test'):
		i.string = var
	# save file again
	with open("templates/index.html", "w") as outf:
		outf.write(str(soup))


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