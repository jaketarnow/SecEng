from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response
from OpenSSL import SSL
from Crypto.PublicKey import RSA
import hashlib
import MySQLdb
import os
import Cookie
import datetime

#context = SSL.Context(SSL.SSLv23_METHOD)
#cer = os.path.join(os.path.dirname(__file__), 'certificate.crt')
#key = os.path.join(os.path.dirname(__file__), 'privateKey.key')
app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

if __name__ == "__main__":
	db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="cs683")
	cur = db.cursor()

class ServerError(Exception):pass

@app.route('/')
def main():
	# Fix with personalized cookie - for Step 4
	# Verify if cookie exists in db
	print request.cookies.get('userID')
	user_id = verifyCookie(request.cookies.get('userID'))
	if user_id:
		return render_template("index.html")
	else:
		return render_template("signup.html")

@app.route('/signup', methods=["POST"])
def signup():
	username_form = request.form["username"]
	password_form = request.form["password"]

	password_form = hashIt(password_form)

	cookie_create = hashlib.sha256(username_form + password_form).hexdigest()
	try:
		sql = "INSERT INTO users (username, password, pubkey, cookies) VALUES ('%s', '%s', '%s', '%s')" %(username_form, password_form, privKeyGeneration().publickey().exportKey(), cookie_create)
		cur.execute(sql)
		db.commit()
	except MySQLdb.IntegrityError:
		raise ServerError("Invalid sql insert")
	resp = make_response(redirect(url_for("main")))
	resp.set_cookie('userID', cookie_create)
	return resp

@app.route('/login', methods=["GET", "POST"])
def login():
	try:
		if request.method == "POST":
			username_form = request.form["username"]
			password_form = request.form["password"]
			password_form = readKey().encrypt(hashIt(password_form), 32)
			print password_form
			try:
				sql = "SELECT * FROM users WHERE username = '%s'" %(username_form)
				cur.execute(sql)
				db.commit()
			except MySQLdb.IntegrityError:
				raise ServerError("Invalid")

			for row in cur.fetchall():
				# Decrypt password
				pubkey = RSA.importKey(row[4])
				decryptPwd = pubkey.decrypt(password_form)

				if decryptPwd == row[2]:
					resp = make_response(redirect(url_for("main")))
					#expire_date = datetime.datetime.now()
					#expire_date = expire_date + datetime.timedelta(days=1)
					resp.set_cookie('userID', row[3], expires=0)
					return resp
	except ServerError as se:
		error = str(se)
	return render_template("login.html")

def verifyCookie(userCookie):
	try:
		sql = "SELECT username FROM users WHERE cookies = '%s'" %(userCookie)
		cur.execute(sql)
		db.commit()
		return True
	except MySQLdb.IntegrityError:
		raise ServerError("Invalid sql insert")
	return False

def privKeyGeneration():
	key = RSA.generate(2048)
	f = open('userKey.pem', 'w')
	f.write(key.exportKey('PEM'))
	f.close()
	return key

def getPubKey():
	f = open('userKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def readKey():
	f = open('userKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key

def hashIt(hashme):
	hashed = hashme
	hash_object = hashlib.sha256(hashed)
	hex_dig = hash_object.hexdigest()
	hashed = hex_dig
	return hashed

@app.route('/logout')
def logout():
	return render_template("signup.html")

if __name__ == "__main__":
	#context = (cer, key)
	#app.run(host='0.0.0.0', debug = True, ssl_context=context)
	app.run(host='0.0.0.0', port=8080, debug = True)