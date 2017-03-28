from flask import Flask, render_template, request, redirect, url_for, session, escape, make_response
from OpenSSL import SSL
from Crypto.PublicKey import RSA
import hashlib
import base64
import MySQLdb
import os
import Cookie
import datetime
import json
import requests
import urllib2
import re
import time

app = Flask(__name__)

app.secret_key = os.urandom(24).encode('hex')

if __name__ == "__main__":
	db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="cs683")
	cur = db.cursor()

class ServerError(Exception):pass
# To adjust the cookie, and make sure users can't do same name 
# fix user name confusion 

@app.route('/api/userInfo', methods=['GET'])
def main():
	user_idz = request.get_data()
	print "In the main of data server"
	print user_idz
	user_id = verifyCookie(user_idz)
	if user_id:
		return_info = {'success': True}
	else:
		return_info = {'success': False}
	return json.dumps(return_info, indent=4)

@app.route('/api/signup', methods=['POST'])
def signup():
	data = request.get_json()
	# if all information is in data then grab it and create cookie on signup
	if 'username' in data and 'password' in data and 'key' in data:
		username = data['username']
		pw = data['password']
		key = data['key']
		ts = time.time()
		server_secret = privKeyGeneration()
		# Cookie is constructed with privateKeyGen and username and time stamp 
		cookie_create = hashlib.sha256(str(server_secret) + username + str(ts)).hexdigest()

		# first check to make sure there is no username that is same already
		try:
			sql = "SELECT * FROM users WHERE username = '%s'" %(username)
			cur.execute(sql)
			db.commit()
		except MySQLdb.IntegrityError:
			raise ServerError("Invalid")
		row_count = cur.rowcount
		if row_count == 0:
			try:
				sql = "INSERT INTO users (username, password, pubkey, cookies) VALUES ('%s', '%s', '%s', '%s')" %(username, pw, key, cookie_create)
				cur.execute(sql)
				db.commit()
			except MySQLdb.IntegrityError:
				raise ServerError("Invalid sql insert")
			json_cookie = {'user':username, 'cookie':cookie_create, 'timestamp':str(ts)}
			print "in signup of data server"
			print json_cookie
			jsonify = {'success': True,'cookie': json_cookie}
		else:
			jsonify = {'success': False}
	else:
		jsonify = {'success': False}
	return json.dumps(jsonify, indent=4)

@app.route('/api/login', methods=['GET', 'POST'])
def login():
	data = request.get_json()
	usern = data['username']
	encryptedHash = data['crypto']
	encryptedHash = base64.b64decode(encryptedHash)
	print encryptedHash

	if encryptedHash != None:
		print "IN HERERRERER for login of data server"
		try:
			sql = "SELECT * FROM users WHERE username = '%s'" %(usern)
			cur.execute(sql)
			db.commit()
		except MySQLdb.IntegrityError:
			raise ServerError("Invalid")
		for row in cur.fetchall():
			decryptPwd = RSA.importKey(row[4]).encrypt(encryptedHash, None)
			# print decryptPwd
			# print "IN FOR LOOPP!!"
			# print decryptPwd[0]
			# print row[2]
			if decryptPwd[0] == row[2]:
				# print "IT IS A SUCCESS!!!!!!!!!!!!"
				jsonify = {'success': True,'cookie': row[3]}
				return json.dumps(jsonify, indent=4)

def privKeyGeneration():
	key = RSA.generate(2048)
	f = open('serversecretKey.pem', 'w')
	f.write(key.exportKey('PEM'))
	f.close()
	return key

def getServerSecret():
	f = open('serversecretKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key

def getPubKey():
	f = open('serversecretKey.pem', 'r')
	key = RSA.importKey(f.read())
	return key.publickey()

def verifyCookie(userCookie):
	print "in verify cookie of data server"
	print type(userCookie)
	cookie_data = userCookie["user_cookie"]
	print cookie_data
	cookie_user = cookie_data[2]["user"]
	print cookie_user
	cookie_ts = cookie_data[0]["timestamp"]
	print cookie_ts
	cookie_cookiez = cookie_data[1]["cookie"]
	print cookie_cookiez
	secret_key = getServerSecret()
	cook_check = checkCookieCred(cookie_cookiez, cookie_user, cookie_ts, secret_key)

	if cook_check:	
		try:
			sql = "SELECT username FROM users WHERE cookies = '%s'" %(userCookie)
			cur.execute(sql)
			db.commit()
			if cur.rowcount > 0:
				return True
		except MySQLdb.IntegrityError:
			raise ServerError("Invalid sql insert")
		return False
	else:
		return False

def checkCookieCred(cookie, username, timestamp, secret_svkey):
	# recreate the hash..rehash the server secret + username + claimed ts
	# then compare that to actual cookie
	# if they match that means that ts was used to create it
	validate_cookie = hashlib.sha256(str(secret_svkey) + username + timestamp).hexdigest()
	curr_time = time.time()
	print "in check cookie cred of data server"
	print str(curr_time)
	print timestamp
	ts_offset = timestamp + 30
	print str(ts_offset)
	
	if str(ts_offset) < ts:
		if validate_cookie == cookie:
			return True
		else:
			return False

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8081, debug = True)