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

@app.route('/api/login', methods=['GET', 'POST'])
def login():
	data = request.get_json()
	usern = data['username']
	pwd = data['password']
	print pwd
	if pwd != None:
		cur.execute("""SELECT * FROM users WHERE username = %s AND password = %s""", (usern, pwd))
		# HOMEWORK - understand commit does beyond to build safe site
		db.commit()
		rows = cur.fetchall()
		print rows
		if not rows:
			print "in here???"
			jsonify = {'success': False, 'answer': 'oops'}
			return json.dumps(jsonify, indent=4)
		else:
			everything = str(cur.fetchall)
			for row in rows:
				if pwd == row[1]:
					jsonify = {'success': True, 'answer': 'here'}
				else:
					jsonify = {'success': False, 'answer': 'oops'}
				return json.dumps(jsonify, indent=4)

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8081, debug = True)