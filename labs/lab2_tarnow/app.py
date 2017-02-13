from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response
from OpenSSL import SSL
import hashlib
import MySQLdb
import os
import Cookie

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
	user_id = request.cookies.get('userID')
	if user_id is not None:
		return render_template("index.html")
	else:
		return render_template("signup.html")

@app.route('/signup', methods=["POST"])
def signup():
	username_form = request.form["username"]
	password_form = request.form["password"]
	hash_object = hashlib.sha256(password_form)
	hex_dig = hash_object.hexdigest()
	password_form = hex_dig
	try:
		sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" %(username_form, password_form)
		cur.execute(sql)
		db.commit()
	except MySQLdb.IntegrityError:
		raise ServerError("Invalid sql insert")
	resp = make_response(redirect(url_for("main")))
	resp.set_cookie('userID', username_form)
	#session['authenticated'] = True
	return resp

@app.route('/login', methods=["GET", "POST"])
def login():
	try:
		if request.method == "POST":
			username_form = request.form["username"]
			password_form = request.form["password"]

			try:
				sql = "SELECT * FROM users WHERE username = '%s'" %(username_form)
				cur.execute(sql)
				db.commit()
			except MySQLdb.IntegrityError:
				raise ServerError("Invalid")

			for row in cur.fetchall():
				if hashlib.sha256(password_form).hexdigest() == row[2]:
					resp = make_response(redirect(url_for("main")))
					resp.set_cookie('userID', username_form)
					return resp
	except ServerError as se:
		error = str(se)
	return render_template("login.html")

@app.route('/logout')
def logout():
	resp = make_response(redirect(url_for("main")))
	resp.set_cookie('userID', '', expires=0)
	return resp

if __name__ == "__main__":
	#context = (cer, key)
	#app.run(host='0.0.0.0', debug = True, ssl_context=context)
	app.run(host='0.0.0.0', debug = True)