# Lab 3
## How to Install/Run
Must have:

1. Python >=2.7
2. pip to install all library dependencies
3. Flask
4. OpenSSL
5. MySQL

Set up MySQL DB and run MySQL Server. Clone the repo and run python app.py. You will notice the IP address and that the app is running on HTTPS. Enjoy!

## Basis
Sniff the packets from a web browser to your server using 1)http and (optional) 2)https while a legitimate user logs in to your website. 
Write a program that takes the packet capture file (txt format is fine), the URL of your website, and launches a replay attack on your website to access the restricted content as the legitimate user. 
Make sure that your web server responds with the restricted content only when the cookie is valid. In other words, this replayed cookie is an authentication cookie. Does the capture file from 1) works? (Optional) How about from 2)?

### With HTTP
With HTTP if you grab the user's login and cookie via WireShark, you can then plug that txt file and requested url into the python
program and gain access to the restricted page. Via python regex of grabbing the cookie from the .txt file and appending headers using urllib2 library we can easily accomplish this.

### With HTTPS
When testing with HTTPS I was unable to gain access because of the SSL Certificate verification. I belive if my cert was not self-signed then I would be able to accomplish this
Error: 
```
urllib2.URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:590)>
```

### Overall
I had to go back and re-do lab2 as I was using Sessions instead of Cookies. Once editing that and re-doing the code, I was able to work through lab3. All of the pcap files from lab2 are still valid, yet you were unable to see the cookies that I have for lab3. 
