# Lab 2
## Basis
The idea behind this implementation was that I wanted to build a web app using Python and Flask as I had not done that in the past before.
The way that I implmeneted the app is that a when a user visits the site, if they have no session already live, then they will be prompted to the sign in page. 
If they do have a session live, then they will see the private page which says "I have your identity!!!". You may only reach that page once logged in via signing up or a general login. 

I prefer the idea that the private page is protected by sessions and isn't even accessable more than having a page that prompts you with an alert. No matter one, if you are not logged in, you will not get to the page.
Plus I like the way that sessions deals with multiple pages being open at once and staying consistent with one's session throughout the browser. 

## Packet Sniff Results
Through Wireshark we were able to see the username and hashed password fly in the cookies on the initial sign up/login. Yet, once a session was activated then the cookies would only hold the session id and nothing else. It is amazing to see how insecure the Internet is when it comes to HTTP instead of using SSL and HTTPS.

## Adding SSL
Using OpenSSl to generate a self-signed key and certificate you can call:
```
> openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt
```
From there you can import SSL from OpenSSL to make your webapp HTTPS.  
