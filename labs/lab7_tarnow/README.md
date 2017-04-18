## Lab7
### Overview
Add a database (e.g. MySQL) as the backend to your website that stores username and password. Build a login website so that you can demonstrate an SQL injection attack that will show all the usernames and passwords. (Hint: your website can login to the database as the admin to read username and password for the user.) This login website should act normally, e.g. this website should not be displaying the username and password in clear in a normal login process even for an admin account. Implement another version of the login website that prevents the attack you showed. (Hint: input sanitization)

### Unsafe Site
For the unsafe site, I made it so when the sql query is executed it never gets committed to the db. So it is run without any actual validation checks. Then as it runs, we only check if we get back a response, not if we get back what we are expecting.
Injection String is: 
```' OR EXISTS(SELECT * FROM users WHERE username LIKE '%k%') AND ''='```


### Safe Site
All of these issues can be checked by making sure that your sql query is within the cursor execute function and you use tuples or %s in place of each variable.
Example: 
```c.execute("""SELECT spam, eggs, sausage FROM breakfast
          WHERE price < %s""", (max_price,))```

This protects from SQL Injection and you are not placing the query as an actual string that could be manipulated.
