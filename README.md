# throwaway_encryption

This project uses AES Encryption on data kept in a SqLite database.
There is one account already registered. Its username is 'username' and its password is 'password'.
To use the app, `dotnet run`.


Registering will create a new entry in the database.
Logging in will set the vlaue of loggedIn from the database.
Updating account will allow a new secret.
Logging out will set the value of loggedIn to `null`
Getting account info will print the value of loggedIn, followed by the value of Secret, which is derived from IV, key, and CipherText using AES.


There is 1 table in the database, with 6 columns.
* UserGuid is a unique primary key
* UserName is the users username
* cleartext is the unencrypted secret.
* ciphertext is the encrypted secret. 
* iv is the initialization vector used for this entry. It is unique to that user.
* passhash is the password's hash + salt. This is generated from Rfc2898DeriveBytes. IT CANNOT BE DECRYPTED.


The encryption key is the static constant 'key' 


There is one extra field in the User object: Secret. It is get-only. It decrypts the CipherText field using the key `key` and the initialization vector `IV`.
