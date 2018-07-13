# HTC Messages backup decryptor

## Setup
Tested with Java 8:
```
javac Decrypt.java
```
Maybe you'll have to 'install' the `Unlimited JCE Policy` to get up to key length
of 192 bits used by the backup.

## Use
```
$ java Decrypt data/HTSMSGBK_2018xxx.hbk > data/plaintext
Max key len: 2147483647
Decrypting with password: htc20100416
```

For backups with custom password set during the backup:
```
$ java Decrypt data/HTSMSGBK_2018xxx.hbk my_backup_password > data/plaintext
Max key len: 2147483647
Decrypting with password: my_backup_password
```

# Analysis notes

`public static final String VALUES_KEY_PASSWORD = "password";`
passwordless password is probably `htc20100416` (`com.htc.sense.mms.ui.wz`)
(updated in the com.cmcc SSO code on login and in the pass dialog on ok)

check `com.htc.sense.mms.ui.BackupActivity.a(String, String)`
which is the encryptor
`this.v` is true if the backup is 'passwordless'
`public static final String SYMMETRIC_ENCRYPTION = "AES";`

Code uses the 'traditional' insecure method to create the key from password,
replacement provided here:
https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html

```
rng = SecureRandom("SHA1PRNG", "Crypto").seed(password)
key = KeyGenerator("AES").init(192, rng).generateKey()
cipher = Cipher("AES").init(2, key, random_bytes)
```