from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response
from OpenSSL import SSL
from Crypto.PublicKey import RSA
import hashlib
import MySQLdb
import os
import Cookie
import datetime
import json
import requests

app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

if __name__ == "__main__":
	db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="cs683")
	cur = db.cursor()

class ServerError(Exception):pass

@app.route('/api/userInfo/<userID>', methods=['GET'])
def main(userID):
	print "in main"
	print userID
	# Fix with personalized cookie - for Step 4
	# Verify if cookie exists in db
	user_id = verifyCookie(userID)
	if user_id:
		return_info = {'success': True}
	else:
		return_info = {'success': False}
	return json.dumps(return_info, indent=4)

@app.route('/api/signup', methods=['POST'])
def signup():
	print "in here"
	data = request.get_json()
	print data
	if 'username' in data and 'password' in data and 'key' in data:
		username = data['username']
		pw = data['password']
		key = data['key']
		cookie_create = hashlib.sha256(username + pw).hexdigest()

		try:
			sql = "INSERT INTO users (username, password, pubkey, cookies) VALUES ('%s', '%s', '%s', '%s')" %(username, pw, key, cookie_create)
			cur.execute(sql)
			db.commit()
		except MySQLdb.IntegrityError:
			raise ServerError("Invalid sql insert")
		jsonify = {'success': True,'cookie': cookie_create}
	else:
		jsonify = {'success': False}
	return json.dumps(jsonify, indent=4)

@app.route('/api/login', methods=['GET', 'POST'])
def login():
	data = request.data
	print "data"
	myList = request.data.split("&")
	userz = myList[0].split("=")
	usern = userz[1]
	crpt = myList[1].split("=")
	crypti = (crpt[1]).decode('utf-8')
	print crypti
	# print request.data.get('username')
	# print "args"
	# print request.args
	# print "json"
	# print request.get_json()
	# print data.get('crypto')
	# print data.get('username')
	if crypti != None:
		print "IN HERERRERER"
		try:
			sql = "SELECT * FROM users WHERE username = '%s'" %(usern)
			cur.execute(sql)
			db.commit()
		except MySQLdb.IntegrityError:
			raise ServerError("Invalid")
		for row in cur.fetchall():
			decryptPwd = RSA.importKey(row[4]).encrypt(crypti, None)
			# print decryptPwd[0]
			# print decryptPwd[0] == row[2]
			print "IN FOR LOOPP!!"
			if decryptPwd[0] == row[2]:
				print "IT IS A SUCCESS!!!!!!!!!!!!"
				jsonify = {'success': True,'cookie': row[3]}
				return json.dumps(jsonify, indent=4)

def verifyCookie(userCookie):
	try:
		sql = "SELECT username FROM users WHERE cookies = '%s'" %(userCookie)
		cur.execute(sql)
		db.commit()
		if cur.rowcount > 0:
			return True
	except MySQLdb.IntegrityError:
		raise ServerError("Invalid sql insert")
	return False

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8081, debug = True)