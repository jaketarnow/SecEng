## Lab 4
### Task
You will implement a server (website) and a client in this step. Let's call your server ZBoxlive.com. When a user sets up an account, ZBoxlive.com provides a unique public and private key pair. You may assume that the account setup is already done, so your client knows the private key and the server knows the username, the hash value of the password, and the corresponding public key.

When the user wants to log into ZBoxlive.com, he or she types in username and password to the client program. The client program sends (username, password hashed and encrypted with his private key) to the server, i.e. (username, Ru < H(password) >), where Ru is the private key of the user, H is a secure hash function and H(password) is a hash value of the password. Based on the username, the server pulls the public key for that user from its database and decrypts the second part using this public key. The descrypted hash value is compared with the hash value stored in the database. If the two values match, access is granted. Assume that ZBoxlive.com does not share the public key of a user with other users.

**ZBoxlive.com is vulnerable to replay attack. Explain the details of the replay attack in README.**
**Modify your website to prevent replay attack. Hint: every login message should be fresh**

### Libraries Used
* [PyCrypto RSA](https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html)
* [JSEncrypt](https://github.com/travist/jsencrypt)
* [jsSHA](https://github.com/Caligatio/jsSHA)

### How It Works
After un-zipping the file, go to lab2 and run
```
python app.py
```

Make sure you also have a MySQL DB instance running with the table configuration of: 
```
CREATE TABLE users (username VARCHAR(150), password VARCHAR(150), cookies VARCHAR(256), pubkey VARCHAR(1024));
```

We assume that the user has already created a public key / private key on their own using OpenSSL. Commands are as follows:
To generate private key:
```
openssl genrsa -out userkey.pem 1024
```
To generate public key from private:
```
openssl rsa -in userkey.pem -pubout -out userkey.pem
```

Once these are created, then when a user sign's up they will upload their public key to the server. Once signed in, the user will have a 30sec cookie. When the user logouts of the site, the cookie will expire. Based on this, every login is fresh.

When a user navigates back to the site to login, they will add their private key for the login which will decrypt with their hashed password. This decryption will be sent to the server and be encrypted with the public key to validate the hashed password. 

### Theory behind RSA Encryption/Decryption
When placed with this task, I asked the professor how are we supposed to encrypt with private key and decrypt with public key, as this goes against the regular protocol. Yet, as she reminded me...that they use the same math.
So, instead of just encrypt decrypt...why not decrypt then encrypt as it does the same thing.  I performed this and it worked. The decryption client-side does have some issues, so I have it going from server-side at the moment. 

In previous commits, I generated the public and private key from the server, but felt this was very insecure as the server will have the private key for a short period of time. 

### Edits to Lab3
Fixed lab3 to parse a .pcap file and grab the cookies from the headers.
I realized that the past pcap files were not pulling in all the HTTP requests/responses because of the host address that I was using. I edited this and it is fully working now. 
