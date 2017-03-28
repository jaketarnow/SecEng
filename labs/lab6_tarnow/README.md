## Lab 6
Implement the man-in-the-middle attack on slide 3 of SSL lecture. 
You will need to implement Alice, Bob, Charlie separately, demonstrate how Alice and Bob work in a normal situation, and also demonstrate how Charlie can sit between Alice and Bob to authenticate himself as Alice to Bob. 

Note that Bob needs to be a website, but you may implement Alice and Charlie as a stand-alone program. 
You may use a 3rd-party RSA library, e.g. PHPseclib.

### Basis

1. Alice Sends to Bob (Message = PublicBob("Alic", Kab)
2. Bob Receives Message (Message = PrivateBob(Message) prints Message
3. Bob Generates a Random Number (Nonce) and sends to Alice (Message = Encrypt with shared key(Nonce))
4. Alice Receives Message (Alice Decrypts) Nonce = Decrypt with Sharked Key(Message)
5. Alice Sends New Message (Message = Encrypt with Kab("Alice", PrivateAlice(Nonce))
6. Bob Receives Message (Bob Decrypts message, Message = DecryptSharedKey(Message), Bob Decrypts signature, Nonce = PublicAlice(Signatrue)

Bob Validates if Nonce was the one sent earlier


Meanwhile Charlie intercepts messages and uses his key to impersonate Alice


### Issues
Having issues with this project, and currently still working on it until I complete it. Will come back and re-submit/upload code once it is passing all test cases.
