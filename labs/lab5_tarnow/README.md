# Lab 5
## How to Install/Run
Must have:

1. Python >=2.7
2. pip to install all library dependencies
3. Flask
4. OpenSSL
5. MySQL

Set up MySQL DB and run MySQL Server. Clone the repo and run python app.py for the client side and run python dataapp.py for data server. You will notice the IP address and that the app is running on HTTP. Enjoy!

## Basis
The idea behind this implementation was that I wanted to build a web app using Python and Flask as I had not done that in the past before.
The way that I implmeneted the app is that a when a user visits the site, if they have no session already live, then they will be prompted to the sign in page. If they already have an account and need to login, then they can go to the /login page. 

If they do have a session live, then they will see the private page which says "I have your identity <name>!!!". You may only reach that page once logged in via signing up or a general login. 

Because this lab was built off of the previous ones, a new user can easily create an account. The only overhead is that the user needs to create their pubkey and privkey on their own. I felt this was the most secure way to do this, so the server never holds onto the private key. If you let the server or client create the keys, then it would have the private key for some time. 

As stated before, a user can login once and then view the private page. When they logout the cookie will be set to expire. An attacker can not impersonate the user to the server. Yet, because we are not using HTTPS and SSL/TLS anything that is sniffable is replayable.
