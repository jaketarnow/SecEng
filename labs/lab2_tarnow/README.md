# Lab 2
## How to Install/Run
Must have:

1. Python >=2.7
2. pip to install all library dependencies
3. Flask
4. OpenSSL
5. MySQL

Set up MySQL DB and run MySQL Server. Clone the repo and run python app.py. You will notice the IP address and that the app is running on HTTPS. Enjoy!

## Basis
The idea behind this implementation was that I wanted to build a web app using Python and Flask as I had not done that in the past before.
The way that I implmeneted the app is that a when a user visits the site, if they have no session already live, then they will be prompted to the sign in page. If they already have an account and need to login, then they can go to the /login page. 

If they do have a session live, then they will see the private page which says "I have your identity!!!". You may only reach that page once logged in via signing up or a general login. 

I prefer the idea that the private page is protected by sessions and isn't even accessable more than having a page that prompts you with an alert. No matter one, if you are not logged in, you will not get to the page.
Plus I like the way that sessions deals with multiple pages being open at once and staying consistent with one's session throughout the browser. 

## Packet Sniff Results
Through Wireshark we were able to see the username and hashed password fly in the cookies on the initial sign up/login. Yet, once a session was activated then the cookies would only hold the session id and nothing else. It is amazing to see how insecure the Internet is when it comes to HTTP instead of using SSL and HTTPS.

## Facebook Sniff Results
When sniffing login to Facebook and logout. All you could see is the client server handshack and the session created. Once you logout then the session is ended and a new session waits to be created. (Look at packet 342). When visiting the dictionary.com site, you can see that everything is encrypted, yet there is a cookie. I looked through packet list and details for facebook or "Like" but did not find anything. I can only assume that the cookie holds something from Facebook as when you go back to Facebook.com it knows that your profile was there before. 

## Adding SSL
After going through the first couple steps with my app running on HTTP, I then created a key and cert to get SSL working.

Using OpenSSl to generate a self-signed key and certificate you can call:
```
> openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt
```
From there you can import SSL from OpenSSL to make your webapp HTTPS. The python code that I added was:
```
context = SSL.Context(SSL.SSLv23_METHOD)
cer = os.path.join(os.path.dirname(__file__), 'certificate.crt')
key = os.path.join(os.path.dirname(__file__), 'privateKey.key')
```
Then down at the bottom when you call app.run() you add in the ssl_context:
```
context = (cer, key)
	app.run(host='0.0.0.0', debug = True, ssl_context=context)
```
I actually really enjoyed this lab as it was challenging to figure out how to set up an application that was not completely safe, yet also figure out how to add SSL. I never fully understood how much of a difference HTTPS and encryption made until sniffing the packets. I did some research and it seems the only way you would be able to actually see all the packet details and cookies is if you also were running some sort of decryption program on the packets. Quite interesting!
